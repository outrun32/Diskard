"""Application service and sequential durable executor for the local console."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from diskard.console.bridge import (
    ExecutionBridge,
    InvestmentExecutionBridge,
    auto_bootstrap_enabled,
)
from diskard.console.contracts import (
    EventRecord,
    RunSpec,
    TargetProfile,
)
from diskard.console.repository import (
    RunStore,
    make_engine,
    migrate,
)
from diskard.console.settings import ConsoleSettings

log = logging.getLogger("diskard.console")


def default_local_profile() -> TargetProfile:
    """Return the zero-configuration profile for the bundled local stand."""
    base_url = os.getenv("DISKARD_TARGET_URL", "http://host.docker.internal:8600")
    return TargetProfile(
        id="investment-local",
        name="Local investment stand",
        adapter="investment-stand",
        base_url=base_url,
        actors={
            "attacker": {"cus": "1001"},
            "trigger_user": {"cus": "1002"},
            "data_subject": {"cus": "1003"},
            "control": {"cus": "1004"},
        },
        adapter_options={
            "auto_bootstrap": True,
            "keycloak_url": "http://host.docker.internal:8180",
            "keycloak_realm": "genai-stand",
            "ui_client_id": "streamlit-ui",
            "agent_api_url": base_url,
            "invest_url": "http://host.docker.internal:8200",
        },
    )


class CheckNotReady(ValueError):
    def __init__(self, checks):
        super().__init__("Цель не готова к проверке. Исправьте подключение или профиль.")
        self.checks = checks


class CancellationFlag:
    def __init__(self) -> None:
        self._event = threading.Event()

    def is_set(self) -> bool:
        return self._event.is_set()

    def set(self) -> None:
        self._event.set()


class ConsoleRuntime:
    def __init__(
        self,
        settings: ConsoleSettings | None = None,
        *,
        bridge_factory: Callable[[], ExecutionBridge] | None = None,
    ) -> None:
        self.settings = settings or ConsoleSettings.from_env()
        self.engine = None
        self.store: RunStore | None = None
        self.bridge: ExecutionBridge = (
            bridge_factory() if bridge_factory is not None else InvestmentExecutionBridge()
        )
        self.lease = None
        self.started = False
        self.startup_error: str | None = None
        self.executor_task: asyncio.Task | None = None
        self.stop_event = asyncio.Event()
        self.cancellations: dict[str, CancellationFlag] = {}

    @property
    def ready(self) -> bool:
        return self.started and self.store is not None and self.startup_error is None

    def start(self) -> None:
        if not self.settings.database_configured:
            self.startup_error = (
                "DISKARD_DATABASE_URL is not configured; copy .env.example and set the "
                "database URL before enabling durable storage"
            )
            return
        try:
            self.engine = make_engine(self.settings.database_url)
            migrate(self.engine)
            self.store = RunStore(self.engine, event_max_bytes=self.settings.event_max_bytes)
            self.store.ping()
            self._import_startup_profiles()
            self._ensure_default_profile()
            self.lease = self.store.acquire_executor()
            self.store.mark_orphans_interrupted()
            self.started = True
            self.stop_event.clear()
            self.executor_task = asyncio.create_task(self._executor_loop())
        except Exception as exc:  # noqa: BLE001
            self.startup_error = (
                f"Console storage/executor is not ready ({type(exc).__name__}). "
                "Check DISKARD_DATABASE_URL, PostgreSQL health and migrations."
            )
            log.error(self.startup_error)
            if self.lease is not None:
                self.lease.release()
                self.lease = None
            if self.engine is not None:
                self.engine.dispose()
                self.engine = None
            self.store = None

    def _import_startup_profiles(self) -> None:
        if self.store is None or not self.settings.profile_file.exists():
            return
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to load DISKARD_PROFILE_FILE") from exc
        raw = yaml.safe_load(self.settings.profile_file.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict) or raw.get("schema_version", 1) != 1:
            raise ValueError("profile file must be a mapping with schema_version: 1")
        targets = raw.get("targets", [])
        if not isinstance(targets, list):
            raise ValueError("profile file targets must be a list")
        for item in targets:
            profile = TargetProfile.model_validate(item)
            result = self.store.upsert_profile(profile)
            if result.get("config_difference"):
                log.warning(
                    "startup profile %s differs from the stored UI version; "
                    "explicit re-import required",
                    profile.id,
                )

    def _ensure_default_profile(self) -> None:
        if self.store is None or self.store.profiles():
            return
        profile = default_local_profile()
        self.store.upsert_profile(profile)
        log.info("created zero-configuration local target profile %s", profile.id)

    async def stop(self) -> None:
        self.started = False
        self.stop_event.set()
        for cancellation in self.cancellations.values():
            cancellation.set()
        if self.executor_task is not None:
            # Cancelling to_thread does not stop its OS thread. Keep the lease until
            # execution and cleanup really finish; container stop is the hard bound.
            await asyncio.shield(self.executor_task)
        if self.lease is not None:
            self.lease.release()
            self.lease = None
        if self.engine is not None:
            self.engine.dispose()
            self.engine = None
        self.started = False

    def require_store(self) -> RunStore:
        if not self.ready or self.store is None:
            raise RuntimeError(self.startup_error or "console storage is not ready")
        return self.store

    def profile(self, profile_id: str) -> dict[str, Any] | None:
        return self.require_store().profile(profile_id)

    def profiles(self) -> list[dict[str, Any]]:
        return self.require_store().profiles()

    async def setup(self) -> dict[str, Any]:
        store_ready = self.ready
        selected = None
        profiles: list[dict[str, Any]] = []
        if store_ready:
            profiles = self.profiles()
            for row in profiles:
                try:
                    selected = TargetProfile.model_validate(row["config"])
                except Exception:  # noqa: BLE001
                    continue
                break
        if selected is None:
            checks = [
                {
                    "id": "database",
                    "label": "Diskard database",
                    "status": "ready" if store_ready else "blocked",
                    "reason": None if store_ready else self.startup_error,
                },
                {
                    "id": "target_api",
                    "label": "target API",
                    "status": "unknown",
                    "reason": "Create or import a target profile to validate it",
                },
                {
                    "id": "actor_credentials",
                    "label": "actor credentials",
                    "status": "unknown",
                    "reason": "Create or import a target profile to validate it",
                },
                {
                    "id": "lifecycle",
                    "label": "lifecycle/state restore",
                    "status": "optional",
                    "detail": "adapter-dependent",
                },
                {
                    "id": "evidence",
                    "label": "evidence collectors",
                    "status": "unknown",
                    "reason": "Create or import a target profile to validate it",
                },
                {
                    "id": "attacker_provider",
                    "label": "attacker provider",
                    "status": "optional",
                    "detail": "template driver does not need an attacker model",
                },
            ]
        else:
            checks = [{"id": "database", "label": "Diskard database", "status": "ready"}]
            checks += [
                {
                    "id": "target_api",
                    "label": "target validation",
                    "status": "unknown",
                    "reason": "Use Validate profile to probe the target explicitly",
                }
            ]
        return {
            "storage_ready": store_ready,
            "executor_owned": self.lease is not None,
            "startup_error": self.startup_error,
            "profiles": [self.public_profile(item) for item in profiles],
            "checks": checks,
            "limitations": [
                "Local release has no authentication and is not safe for public hosting.",
                "Diskard database is separate from the target's memory database.",
                "Executor ownership serializes this installation only; use a dedicated "
                "target/profile for live acceptance.",
            ],
            "secret_instructions": (
                "The bundled local investment profile bootstraps its standard test "
                "identities automatically. Custom profiles can use referenced *_ENV "
                "values in .env or mount files below /run/secrets or /config/secrets. "
                "The console shows only configured/missing state."
            ),
        }

    def public_profile(self, row: dict[str, Any]) -> dict[str, Any]:
        config = row.get("config") or {}
        actors = config.get("actors", {})
        auto_bootstrap = auto_bootstrap_enabled(TargetProfile.model_validate(config))
        public_actors = {}
        for role, actor in actors.items():
            refs = {
                key: value
                for key, value in actor.items()
                if (key.endswith("_env") or key.endswith("_file")) and value is not None
            }
            configured = any(
                (key.endswith("_env") and bool(os.getenv(value)))
                or (key.endswith("_file") and bool(value))
                for key, value in refs.items()
            )
            if auto_bootstrap:
                configured = True
            public_actors[role] = {
                "cus": actor.get("cus"),
                "credential_refs": refs,
                "configured": configured,
                "auto_bootstrap": auto_bootstrap,
            }
        return {
            "id": row["id"],
            "name": row["name"],
            "adapter": row["adapter"],
            "version": row["version"],
            "config": config,
            "actor_status": public_actors,
            "config_digest": row.get("config_digest"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
        }

    def catalog(self, profile_id: str | None) -> dict[str, Any]:
        if profile_id and self.ready:
            row = self.profile(profile_id)
            if row is not None:
                try:
                    profile = TargetProfile.model_validate(row["config"])
                except Exception as exc:  # noqa: BLE001
                    return {
                        "adapter": row.get("adapter"),
                        "attacks": [],
                        "drivers": [],
                        "limitations": [f"Stored profile is not runnable: {exc}"],
                    }
                report = self.bridge.capabilities(profile)
                return {
                    "adapter": report.adapter,
                    "attacks": report.attacks,
                    "drivers": report.drivers,
                    "limitations": report.limitations,
                }
        return {
            "adapter": None,
            "attacks": [
                {
                    "id": "select-profile",
                    "label": "Select a target profile",
                    "available": False,
                    "requirements": ["target profile"],
                }
            ],
            "drivers": [],
            "limitations": ["No target profile is stored yet."],
        }

    def create_run(
        self,
        *,
        profile_id: str,
        attack: str,
        driver: str,
        options: dict[str, Any],
        origin: str,
        submission_id: str | None,
        parent_run_id: str | None = None,
    ) -> dict[str, Any]:
        store = self.require_store()
        row = store.profile(profile_id)
        if row is None:
            raise KeyError(f"unknown target profile {profile_id!r}")
        profile = TargetProfile.model_validate(row["config"])
        capabilities = self.bridge.capabilities(profile)
        attack_capability = next(
            (item for item in capabilities.attacks if item["id"] == attack), None
        )
        driver_capability = next(
            (item for item in capabilities.drivers if item["id"] == driver), None
        )
        if attack_capability is None or not attack_capability.get("available"):
            raise ValueError((attack_capability or {}).get("reason", "attack is unavailable"))
        if driver_capability is None or not driver_capability.get("available"):
            raise ValueError((driver_capability or {}).get("reason", "driver is unavailable"))
        budget = int(options.get("budget", 1))
        repeat = int(options.get("repeat", 1))
        if budget < 1 or budget > 20 or repeat != 1:
            raise ValueError("budget must be between 1 and 20; repeat is fixed at 1")
        if driver == "template" and budget != 1:
            raise ValueError("fixed-input driver requires budget=1")
        run_id = uuid4().hex
        manifest = {
            "schema_version": 1,
            "driver": driver,
            "scenario_version": attack,
            "parameters": options,
            "source_sha": self.settings.build_sha,
            "payload": {},
            "credential_refs": row.get("credential_refs", {}),
            "state_requirements": {"restore": "unsupported"},
            "resolved_inputs": {},
            "complete": False,
            "unsupported_reasons": [
                "current scenario bridge does not expose exact resolved inputs"
            ],
        }
        return store.create_run(
            run_id=run_id,
            profile=row,
            mode="rerun" if parent_run_id else "experiment",
            origin=origin,
            attack=attack,
            driver=driver,
            options=options,
            parent_run_id=parent_run_id,
            client_submission_id=submission_id,
            replay_spec=manifest,
            source_sha=self.settings.build_sha,
        )

    async def create_check(
        self, profile_id: str, attacks: list[str] | None, driver: str, submission_id: str
    ) -> dict[str, Any]:
        store = self.require_store()
        profile = store.profile(profile_id)
        if profile is None:
            raise ValueError("Unknown target profile")
        capabilities = self.bridge.capabilities(TargetProfile.model_validate(profile["config"]))
        available = [item["id"] for item in capabilities.attacks if item.get("available")]
        selected = available if attacks is None else list(dict.fromkeys(attacks))
        if not selected or any(attack not in available for attack in selected):
            raise ValueError("Select at least one available attack")
        if not any(item["id"] == driver and item.get("available") for item in capabilities.drivers):
            raise ValueError("Selected driver is unavailable")
        existing = store.check_submission(submission_id)
        if existing is None:
            readiness = await self.bridge.validate(
                TargetProfile.model_validate(profile["config"]), selected
            )
            if not readiness.ready:
                raise CheckNotReady(readiness.checks)
        return store.create_check(
            profile=profile,
            attacks=selected,
            driver=driver,
            submission_id=submission_id,
            source_sha=self.settings.build_sha,
        )

    def cancel(self, run_id: str) -> dict[str, Any] | None:
        store = self.require_store()
        result = store.request_cancel(run_id)
        if result and result["status"] == "cancelling":
            self.cancellations.setdefault(run_id, CancellationFlag()).set()
        return result

    async def rerun(self, run_id: str, *, profile_id: str | None = None) -> dict[str, Any]:
        store = self.require_store()
        saved = store.run(run_id)
        if saved is None:
            return None
        snapshot = saved.get("config_snapshot") or {}
        if saved.get("mode") == "legacy-import":
            raise ValueError("legacy records have no executable profile snapshot")
        if saved["status"] in {"queued", "running", "cancelling"}:
            raise ValueError("wait for the parent run to finish before rerunning")
        if profile_id is None:
            profile = TargetProfile.model_validate(snapshot["profile"])
            manifest = saved.get("replay_spec") or {}
            if manifest.get("complete") and saved.get("source_sha") != self.settings.build_sha:
                raise ValueError("exact rerun requires the original source build")
            return store.create_run(
                run_id=uuid4().hex,
                profile={
                    "id": profile.id,
                    "version": saved["target_profile_version"],
                    "config": profile.model_dump(mode="json"),
                },
                mode="rerun",
                origin="console-rerun",
                attack=snapshot["attack"],
                driver=snapshot["driver"],
                options=snapshot.get("options") or {},
                source_sha=self.settings.build_sha,
                parent_run_id=run_id,
                replay_spec=manifest,
            )
        selected_profile = profile_id or saved["target_profile_id"]
        options = snapshot.get("options") or {"budget": 1, "repeat": 1}
        return self.create_run(
            profile_id=selected_profile,
            attack=str(snapshot.get("attack") or saved["scenario_version"]),
            driver=str(snapshot.get("driver") or "template"),
            options=options,
            origin="console-rerun",
            submission_id=f"rerun:{run_id}:{uuid4().hex}",
            parent_run_id=run_id,
        )

    async def _executor_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                store = self.require_store()
                self.lease.check()
                claimed = await asyncio.to_thread(store.claim_next_run)
                if claimed is None:
                    await asyncio.sleep(self.settings.executor_poll_seconds)
                    continue
                await self._execute(claimed)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.startup_error = (
                    f"Executor stopped safely ({type(exc).__name__}); "
                    "restart after checking storage"
                )
                log.error(self.startup_error)
                self.stop_event.set()
                for cancellation in self.cancellations.values():
                    cancellation.set()

    async def _execute(self, row: dict[str, Any]) -> None:
        store = self.require_store()
        run_id = row["id"]
        cancellation = self.cancellations.setdefault(run_id, CancellationFlag())
        snapshot = row.get("config_snapshot") or {}
        run_spec = None
        try:
            profile = TargetProfile.model_validate(snapshot["profile"])
            attack = str(snapshot.get("attack") or row["scenario_version"])
            driver = str(snapshot.get("driver") or "template")
            options = snapshot.get("options") or {"budget": 1, "repeat": 1}
            run_spec = RunSpec(
                run_id=run_id,
                profile=profile,
                attack=attack,
                driver=driver,
                options=options,
                resolved_manifest=(store.run(run_id, include_events=False) or {}).get("replay_spec")
                or {
                    "schema_version": 1,
                    "driver": driver,
                    "scenario_version": attack,
                    "parameters": options,
                    "source_sha": row.get("source_sha", self.settings.build_sha),
                    "credential_refs": {},
                    "state_requirements": {"restore": "unsupported"},
                    "resolved_inputs": {},
                    "payload": {},
                },
            )

            def sink(record: EventRecord) -> None:
                if self.lease is not None:
                    self.lease.check()
                store.append_event(run_id, record)
                if record.type == "replay.resolved":
                    store.save_replay(run_id, record.data)

            store.append_event(
                run_id, EventRecord(type="executor.claimed", data={"owner": "local"})
            )
            result = await asyncio.to_thread(
                lambda: asyncio.run(self.bridge.execute(run_spec, sink, cancellation))
            )
            status = "cancelled" if cancellation.is_set() else result.status
            store.finalize(
                run_id,
                status=status,
                raw_engine_result=result.raw,
                summary=result.summary,
                replay_spec=result.replay_spec,
                error=result.error,
                isolation_status=result.isolation_status,
                finding=result.finding,
            )
        except Exception as exc:  # noqa: BLE001
            # Detailed operation errors have already been redacted by the bridge.
            # Unknown exceptions may contain unlabelled provider credentials.
            error = f"Execution failed ({type(exc).__name__}); inspect persisted operation events"
            try:
                store.append_event(
                    run_id, EventRecord(type="executor.error", data={"error": error})
                )
                store.finalize(
                    run_id,
                    status="cancelled" if cancellation.is_set() else "failed",
                    raw_engine_result={"error": error},
                    summary={"verdict": "unknown", "message": error},
                    replay_spec=(store.run(run_id, include_events=False) or {}).get("replay_spec")
                    or {},
                    error=error,
                    isolation_status={"state": "unknown", "reason": "execution failure"},
                )
            except Exception:
                log.exception("failed to persist terminal error for run %s", run_id)
        finally:
            self.cancellations.pop(run_id, None)
