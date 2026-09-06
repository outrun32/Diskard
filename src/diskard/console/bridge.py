"""Execution bridge: adapt the existing scenarios to the durable console contract."""

from __future__ import annotations

import asyncio
import inspect
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import httpx

from diskard.checks.evidence import operation_actor_id, operation_label, operation_message
from diskard.console.contracts import (
    CapabilityReport,
    EngineResult,
    EventRecord,
    ReadinessReport,
    ReplaySupport,
    RunSpec,
    TargetProfile,
)
from diskard.console.redaction import redact
from diskard.evidence import attacker_feedback_from_bundle, evidence_bundle_from_details
from diskard.models import RunPresentation
from diskard.report import aggregate_run_metrics, confidence_for


class CancellationToken(Protocol):
    def is_set(self) -> bool: ...


EventSink = Callable[[EventRecord], Awaitable[None] | None]


class ExecutionBridge(Protocol):
    def capabilities(self, profile: TargetProfile) -> CapabilityReport: ...

    async def validate(
        self, profile: TargetProfile, attacks: list[str] | None = None
    ) -> ReadinessReport: ...

    async def execute(
        self, run_spec: RunSpec, event_sink: EventSink, cancellation: CancellationToken
    ) -> EngineResult: ...

    def replay_support(self, saved_run: dict[str, Any]) -> ReplaySupport: ...


class BridgeError(RuntimeError):
    pass


KNOWN_ATTACKS = (
    "cross-user-global-policy-poisoning",
    "cross-user-direct-memory-leak",
    "compaction-policy-poisoning",
    "delayed-recommendation-manipulation",
)


def _read_ref(
    env_name: str | None,
    file_name: str | None,
    *,
    secret_roots: tuple[Path, ...],
) -> str | None:
    if env_name:
        return os.getenv(env_name)
    if not file_name:
        return None
    requested = Path(file_name)
    if not requested.is_absolute():
        raise BridgeError("credential_file must be an absolute mounted secret path")
    if any(part == ".." for part in requested.parts):
        raise BridgeError("credential_file may not contain parent traversal")
    requested = requested.resolve()
    if not any(requested.is_relative_to(root.resolve()) for root in secret_roots):
        raise BridgeError("credential_file must be under /run/secrets or /config/secrets")
    return requested.read_text(encoding="utf-8").strip()


def _url_is_supported(base_url: str) -> bool:
    return "/models/chat/completions" not in base_url


def auto_bootstrap_enabled(profile: TargetProfile) -> bool:
    configured = profile.adapter_options.get("auto_bootstrap")
    if configured is not None:
        return configured is True
    if profile.id == "investment-local":
        return True
    # Keep the already-created local profile usable after upgrading an installation.
    expected_actors = {
        "attacker": "1001",
        "trigger_user": "1002",
        "data_subject": "1003",
        "control": "1004",
    }
    return (
        profile.adapter == "investment-stand"
        and profile.base_url == "http://host.docker.internal:8600"
        and all(
            profile.actors.get(role) is not None and profile.actors[role].cus == cus
            for role, cus in expected_actors.items()
        )
    )


def _suite_status(suite_result: Any) -> str:
    status = getattr(suite_result, "status", None)
    if status is not None:
        return str(getattr(status, "value", status))
    for scenario_result in suite_result.results:
        for step in scenario_result.steps:
            if step.error is not None:
                return "error"
            for check in step.results:
                if getattr(check.status, "value", check.status) not in {"pass", "fail"}:
                    return "error"
                if getattr(check.status, "value", check.status) == "fail":
                    return "fail"
    return "pass"


class InvestmentExecutionBridge:
    """Compatibility bridge over the four existing investment scenarios.

    It intentionally records adapter-visible operations only. The target's
    private model/tool spans are not available through the current protocol.
    """

    def __init__(
        self, *, secret_roots: tuple[Path, ...] = (Path("/run/secrets"), Path("/config/secrets"))
    ) -> None:
        self.secret_roots = secret_roots
        self._api_keys: dict[tuple[str, str], str] = {}

    @staticmethod
    def _bootstrap(profile: TargetProfile) -> Any:
        from examples.connectors.investment_stand.identity import KeycloakBootstrap

        options = profile.adapter_options
        return KeycloakBootstrap(
            keycloak_url=str(options.get("keycloak_url", "http://host.docker.internal:8180")),
            realm=str(options.get("keycloak_realm", "genai-stand")),
            ui_client_id=str(options.get("ui_client_id", "streamlit-ui")),
            ui_client_secret=str(options.get("ui_client_secret", "streamlit-ui-secret")),
            agent_api_url=str(options.get("agent_api_url", profile.base_url)),
        )

    def capabilities(self, profile: TargetProfile) -> CapabilityReport:
        supported = profile.adapter == "investment-stand"
        attacks = [
            {
                "id": name,
                "label": name,
                "available": supported,
                "requirements": ["target_api", "attacker_credentials", "evidence_collectors"],
                "reason": None
                if supported
                else "investment-stand bridge is the only integrated adapter",
            }
            for name in KNOWN_ATTACKS
        ]
        drivers = [
            {
                "id": "template",
                "label": "Fixed scenario input",
                "available": supported,
                "reason": None if supported else "adapter unavailable",
            },
            {
                "id": "llm-auto-attacker",
                "label": "LLM auto-attacker",
                "available": False,
                "reason": (
                    "Durable search is not integrated; fixed-input scenarios remain available"
                ),
            },
        ]
        return CapabilityReport(
            adapter=profile.adapter,
            attacks=attacks,
            drivers=drivers,
            limitations=[
                "Adapter-visible HTTP and evidence operations are captured; "
                "target-internal LLM/tool spans are unavailable.",
                "Target state restore is not implemented; use a dedicated target/profile "
                "for live acceptance.",
            ],
        )

    async def validate(
        self, profile: TargetProfile, attacks: list[str] | None = None
    ) -> ReadinessReport:
        checks: list[dict[str, Any]] = []
        if profile.adapter != "investment-stand":
            return ReadinessReport(
                checks=[
                    {
                        "id": "adapter",
                        "label": "adapter",
                        "status": "blocked",
                        "reason": "Only investment-stand is integrated in this release",
                    }
                ]
            )
        checks.append(
            {"id": "adapter", "label": "adapter", "status": "ready", "detail": profile.adapter}
        )
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(profile.base_url + "/healthz")
            checks.append(
                {
                    "id": "target_api",
                    "label": "target API",
                    "status": "ready" if 200 <= response.status_code < 300 else "blocked",
                    "detail": f"HTTP {response.status_code}",
                    "reason": None
                    if 200 <= response.status_code < 300
                    else "expected a reachable HTTP endpoint",
                }
            )
        except Exception as exc:  # noqa: BLE001
            checks.append(
                {"id": "target_api", "label": "target API", "status": "blocked", "reason": str(exc)}
            )

        selected = set(KNOWN_ATTACKS if attacks is None else attacks)
        auto_bootstrap = auto_bootstrap_enabled(profile)
        required_roles = {"attacker", "trigger_user"}
        if selected & {"cross-user-global-policy-poisoning", "compaction-policy-poisoning"}:
            required_roles.add("data_subject")
        if "delayed-recommendation-manipulation" in selected:
            required_roles.add("control")
        bootstrap_error: str | None = None
        if auto_bootstrap and all(role in profile.actors for role in required_roles):
            try:
                await self._actors(profile, required_roles=required_roles)
            except Exception as exc:  # noqa: BLE001
                bootstrap_error = str(redact(str(exc)))
        for role in sorted(required_roles):
            actor = profile.actors.get(role)
            if actor is None:
                checks.append(
                    {
                        "id": f"actor:{role}",
                        "label": f"{role} credentials",
                        "status": "blocked",
                        "reason": "profile does not define this required actor",
                    }
                )
                continue
            try:
                configured = bool(
                    _read_ref(
                        actor.credential_env, actor.credential_file, secret_roots=self.secret_roots
                    )
                )
                if role == "data_subject":
                    configured = configured and bool(
                        _read_ref(
                            actor.access_token_env,
                            actor.access_token_file,
                            secret_roots=self.secret_roots,
                        )
                    )
            except (OSError, BridgeError):
                configured = False
            detail = actor.credential_env or actor.credential_file or "not configured"
            if auto_bootstrap and not (actor.credential_env or actor.credential_file):
                detail = "automatic local bootstrap"
            ready = bootstrap_error is None if auto_bootstrap else configured
            reason = None
            if not ready:
                reason = (
                    f"automatic local bootstrap failed: {bootstrap_error}"
                    if auto_bootstrap and bootstrap_error
                    else "set the referenced env variable or mounted secret file"
                )
            checks.append(
                {
                    "id": f"actor:{role}",
                    "label": f"{role} credentials",
                    "status": "ready" if ready else "blocked",
                    "detail": detail,
                    "reason": reason,
                }
            )

        mongo_ref = profile.adapter_options.get("mongo_uri_env")
        mongo_uri = os.getenv(str(mongo_ref)) if mongo_ref else None
        if not mongo_uri and auto_bootstrap:
            mongo_uri = str(
                profile.adapter_options.get("mongo_uri", "mongodb://host.docker.internal:27017")
            ) or None
        mongo_configured = bool(mongo_uri)
        checks.append(
            {
                "id": "evidence:mongo",
                "label": "Mongo evidence collector",
                "status": "ready" if mongo_configured else "blocked",
                "detail": mongo_ref or mongo_uri or "missing mongo_uri_env",
                "reason": None
                if mongo_configured
                else "configure a non-secret Mongo URI reference",
            }
        )
        invest_url = profile.adapter_options.get("invest_url")
        checks.append(
            {
                "id": "evidence:invest",
                "label": "portfolio canary collector",
                "status": "ready"
                if invest_url
                else "blocked"
                if "data_subject" in required_roles
                else "optional",
                "detail": invest_url or "missing adapter_options.invest_url",
                "reason": None if invest_url else "configure the invest-server URL",
            }
        )
        attacker_base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        attacker_ready = bool(os.getenv("OPENAI_API_KEY")) and _url_is_supported(attacker_base)
        checks.append(
            {
                "id": "attacker_provider",
                "label": "attacker provider",
                "status": "ready" if attacker_ready else "optional",
                "detail": "configured" if attacker_ready else "template driver remains available",
                "reason": (
                    None
                    if attacker_ready
                    else (
                        "LLM driver disabled; OPENAI_API_KEY and a /v1-compatible "
                        "base URL are required"
                    )
                ),
            }
        )
        checks.append(
            {
                "id": "lifecycle",
                "label": "lifecycle/state restore",
                "status": "optional",
                "detail": "not supplied by the current adapter",
            }
        )
        return ReadinessReport(checks=checks)

    async def _actors(self, profile: TargetProfile, *, required_roles: set[str]) -> dict[str, Any]:
        from examples.connectors.investment_stand.models import Actor

        result: dict[str, Actor] = {}
        auto_bootstrap = auto_bootstrap_enabled(profile)
        bootstrap = None
        if auto_bootstrap:
            bootstrap = self._bootstrap(profile)
        key_scope = str(profile.adapter_options.get("agent_api_url", profile.base_url)).rstrip("/")
        for role in required_roles:
            spec = profile.actors.get(role)
            if spec is None:
                raise BridgeError(f"profile is missing actor role {role!r}")
            api_key = _read_ref(
                spec.credential_env,
                spec.credential_file,
                secret_roots=self.secret_roots,
            )
            access_token = _read_ref(
                spec.access_token_env,
                spec.access_token_file,
                secret_roots=self.secret_roots,
            )
            if auto_bootstrap and bootstrap is not None:
                if role == "data_subject":
                    # Keycloak access tokens are short-lived; never trust a persisted env value.
                    access_token = await bootstrap.get_user_access_token(spec.cus)
                if not api_key:
                    api_key = self._api_keys.get((key_scope, spec.cus))
                    if not api_key:
                        if not access_token:
                            access_token = await bootstrap.get_user_access_token(spec.cus)
                        api_key = await bootstrap.create_api_key(access_token)
                        self._api_keys[(key_scope, spec.cus)] = api_key
            if not api_key:
                raise BridgeError(f"credential reference for actor role {role!r} is not configured")
            result[role] = Actor(cus=spec.cus, api_key=api_key, access_token=access_token)
        return result

    async def execute(
        self, run_spec: RunSpec, event_sink: EventSink, cancellation: CancellationToken
    ) -> EngineResult:
        from types import SimpleNamespace

        from giskard.checks import Suite

        from diskard.cli import _build_scenario
        from examples.connectors.investment_stand.backend import (
            InvestServerEvidence,
            MongoEvidence,
            SemanticMemoryEvidence,
            StandClient,
        )
        from examples.connectors.investment_stand.legacy_dispatch import make_dispatch

        if run_spec.driver != "template":
            return EngineResult(
                status="failed",
                raw={"error": "driver unsupported", "driver": run_spec.driver},
                summary={
                    "message": "The durable bridge currently supports template scenarios only."
                },
                replay_spec={
                    **run_spec.resolved_manifest,
                    "complete": False,
                    "unsupported_reasons": ["durable LLM search is not exposed"],
                },
                error="driver unsupported by durable bridge",
            )
        required = {"attacker", "trigger_user"}
        if run_spec.attack in {"cross-user-global-policy-poisoning", "compaction-policy-poisoning"}:
            required.add("data_subject")
        if run_spec.attack == "delayed-recommendation-manipulation":
            required.add("control")
        actors = await self._actors(run_spec.profile, required_roles=required)
        secret_values = tuple(
            value
            for actor in actors.values()
            for value in (actor.api_key, actor.access_token)
            if value
        )
        config = run_spec.profile
        mongo_ref = config.adapter_options.get("mongo_uri_env")
        mongo_uri = os.getenv(str(mongo_ref)) if mongo_ref else None
        if not mongo_uri and auto_bootstrap_enabled(config):
            mongo_uri = str(
                config.adapter_options.get("mongo_uri", "mongodb://host.docker.internal:27017")
            ) or None
        if not mongo_uri:
            raise BridgeError("Mongo evidence collector is not configured")
        secret_values += (mongo_uri,)
        invest_url = str(config.adapter_options.get("invest_url", ""))
        if not invest_url and "data_subject" in required:
            raise BridgeError("adapter_options.invest_url is required")
        stand = StandClient(config.base_url)
        mongo = MongoEvidence(mongo_uri=mongo_uri)
        invest = InvestServerEvidence(base_url=invest_url or config.base_url)
        semantic = SemanticMemoryEvidence(mongo_uri=mongo_uri)
        actor_by_cus = {actor.cus: actor for actor in actors.values()}
        cleanup_key: str | None = None

        async def emit(record: EventRecord) -> None:
            outcome = event_sink(record)
            if inspect.isawaitable(outcome):
                await outcome

        async def wrapped_dispatch(inputs: Any, trace: Any) -> dict[str, Any]:
            if cancellation.is_set():
                raise BridgeError("cancellation requested at operation boundary")
            label = operation_label(inputs)
            actor_id = operation_actor_id(inputs)
            payload = getattr(inputs, "payload", {})
            operation_data = {
                "label": label,
                "phase": inputs.phase,
                "message": operation_message(inputs),
                "auth_mode": payload.get("auth_mode", getattr(inputs, "auth_mode", None)),
            }
            await emit(
                EventRecord(
                    type="operation.started",
                    actor_id=actor_id,
                    session_id=inputs.session_id,
                    operation_id=label,
                    data=redact(operation_data, secret_values),
                    source_timestamp=datetime.now(UTC),
                )
            )
            try:
                outputs = await base_dispatch(inputs, trace)
            except Exception as exc:  # noqa: BLE001
                await emit(
                    EventRecord(
                        type="operation.error",
                        actor_id=actor_id,
                        session_id=inputs.session_id,
                        operation_id=label,
                        data=redact({"error": str(exc), **operation_data}, secret_values),
                        source_timestamp=datetime.now(UTC),
                    )
                )
                raise
            await emit(
                EventRecord(
                    type="operation.completed",
                    actor_id=actor_id,
                    session_id=inputs.session_id,
                    operation_id=label,
                    data=redact({**operation_data, "output": outputs}, secret_values),
                    source_timestamp=datetime.now(UTC),
                )
            )
            return outputs

        base_dispatch = make_dispatch(
            stand=stand,
            mongo=mongo,
            invest=invest,
            identities=actor_by_cus,
            semantic=semantic,
        )
        role_cus = {role: spec.cus for role, spec in config.actors.items() if role in actors}
        args = SimpleNamespace(
            attack=run_spec.attack,
            poisoner_cus=role_cus["attacker"],
            victim_cus=role_cus["trigger_user"],
            data_subject_cus=role_cus.get("data_subject", role_cus["attacker"]),
            control_cus=role_cus.get("control", role_cus["trigger_user"]),
            activation_strategy="default",
        )
        scenario, cleanup_key = _build_scenario(args, wrapped_dispatch, run_spec.run_id)
        operations = [
            interaction.inputs for step in scenario.steps for interaction in step.interacts
        ]
        saved_inputs = run_spec.resolved_manifest.get("resolved_inputs", {}).get("operations")
        role_by_cus = {cus: role for role, cus in role_cus.items()}
        if run_spec.resolved_manifest.get("complete"):
            if not isinstance(saved_inputs, list) or len(saved_inputs) != len(operations):
                raise BridgeError("saved operations do not match this scenario build")
            for operation, saved in zip(operations, saved_inputs, strict=True):
                actor_id = operation_actor_id(operation)
                if (operation_label(operation), operation.phase, role_by_cus[actor_id]) != (
                    saved["label"],
                    saved["phase"],
                    saved["actor_role"],
                ):
                    raise BridgeError("saved operation topology or actor roles changed")
                # Retain freshly generated session IDs, but never regenerate payloads.
                operation.payload["message"] = saved["message"]
                operation.payload["auth_mode"] = saved["auth_mode"]
        resolved = [
            {
                "label": operation_label(op),
                "phase": op.phase,
                "actor_role": role_by_cus[operation_actor_id(op)],
                "message": operation_message(op),
                "auth_mode": op.payload.get("auth_mode"),
                "session_slot": op.session_id.replace(run_spec.run_id, "{run_id}")
                if op.session_id
                else None,
            }
            for op in operations
        ]
        replay_spec = {
            **run_spec.resolved_manifest,
            "scenario_version": run_spec.attack,
            "resolved_inputs": {"operations": resolved},
            "complete": redact(resolved, secret_values) == resolved,
            "unsupported_reasons": [],
            "state_requirements": {
                "restore": "unsupported",
                "sessions": "fresh per rerun",
                "limitation": "exact inputs do not guarantee identical target state or output",
            },
        }
        if not replay_spec["complete"]:
            replay_spec["unsupported_reasons"] = ["input contained credentials and was redacted"]
        try:
            await emit(
                EventRecord(
                    type="replay.resolved",
                    data=redact(replay_spec, secret_values),
                    source="console",
                )
            )
            await emit(
                EventRecord(
                    type="run.started",
                    data={
                        "scenario": scenario.name,
                        "attack": run_spec.attack,
                        "driver": run_spec.driver,
                    },
                    source="console",
                )
            )
            suite_result = await Suite(
                name=f"diskard-console-{run_spec.run_id}", scenarios=[scenario]
            ).run(return_exception=True)
            step = suite_result.results[0].steps[0]
            if step.error is not None:
                error = str(redact(step.error.summary(), secret_values))
                await emit(EventRecord(type="run.error", data={"error": error}))
                return EngineResult(
                    status="failed",
                    raw={"suite_status": _suite_status(suite_result), "step_error": error},
                    summary={"message": error, "scenario": scenario.name},
                    replay_spec=replay_spec,
                    error=error,
                )
            check_result = step.results[0]
            details = redact(check_result.details, secret_values)
            check_status = str(check_result.status.value)
            evidence = evidence_bundle_from_details(
                run_id=run_spec.run_id,
                mode="grey-box",
                details=details,
                attempt=1,
            )
            finding_observed = check_status == "fail"
            metrics = aggregate_run_metrics(
                [
                    {
                        "run_id": run_spec.run_id,
                        "check_status": check_status,
                        "details": details,
                        "finding": finding_observed,
                    }
                ]
            )
            presentation = RunPresentation(
                timeline=evidence.events,
                stages=evidence.stage_verdicts,
                attempts=[attacker_feedback_from_bundle(attempt=1, bundle=evidence)],
                metrics=metrics,
                isolation={"enabled": False, "verified": None},
            ).model_dump(mode="json")
            summary = {
                "scenario": scenario.name,
                "check_status": check_status,
                "message": redact(check_result.message, secret_values),
                "details": details,
                "verdict": {"fail": "vulnerable", "pass": "clean"}.get(check_status, "unknown"),
                "presentation": presentation,
            }
            for event in evidence.events:
                await emit(
                    EventRecord(
                        type=f"evidence.{event.type}",
                        actor_id=event.actor_id,
                        session_id=event.session_id,
                        operation_id=event.phase,
                        data=event.model_dump(mode="json"),
                        source=event.source,
                    )
                )
            await emit(
                EventRecord(
                    type="run.result",
                    data=summary,
                    source="console",
                )
            )
            finding = None
            if check_status == "fail":
                finding = {
                    "id": f"{run_spec.run_id}-finding",
                    "engine_verdict": check_status,
                    "confidence": confidence_for(check_result.details),
                    "stage_results": evidence.stage_verdicts,
                    "evidence_ids": [event.id for event in evidence.events],
                    "raw_engine_payload": {
                        "message": check_result.message,
                        "details": details,
                        "presentation": presentation,
                    },
                }
            return EngineResult(
                status="cancelled"
                if cancellation.is_set()
                else ("completed" if check_status in {"pass", "fail"} else "failed"),
                raw={
                    "suite_status": _suite_status(suite_result),
                    "check_status": check_status,
                    "message": redact(check_result.message, secret_values),
                    "details": details,
                    "presentation": presentation,
                },
                summary=summary,
                error=None
                if check_status in {"pass", "fail"}
                else "engine check did not produce a verdict",
                replay_spec=replay_spec,
                finding=finding,
                isolation_status={
                    "state": "cleanup-attempted",
                    "target_reset": "session-scoped cleanup only",
                    "limitation": "another process can mutate the same target",
                },
            )
        finally:
            # Do not wipe an actor's pre-existing semantic memories. This adapter
            # currently exposes only user-wide deletion for that collection.
            try:
                if cleanup_key is not None:
                    await emit(EventRecord(type="cleanup.started", data={"session": cleanup_key}))
                    await asyncio.to_thread(mongo.delete_by_source_session, cleanup_key)
                await emit(
                    EventRecord(
                        type="cleanup.completed",
                        data={
                            "policy_session": cleanup_key,
                            "semantic": "not restored: adapter has no run-scoped delete",
                        },
                    )
                )
            finally:
                await stand.aclose()
                await invest.aclose()
                for collector in (mongo, semantic):
                    collection = getattr(collector, "_col", None)
                    if collection is not None:
                        collection.database.client.close()

    def replay_support(self, saved_run: dict[str, Any]) -> ReplaySupport:
        spec = saved_run.get("replay_spec") or {}
        if spec.get("complete"):
            return ReplaySupport(True, True, "Exact resolved-input rerun")
        return ReplaySupport(
            True,
            False,
            "Run same configuration again",
            list(spec.get("unsupported_reasons") or ["resolved inputs were not captured"]),
        )


class FakeExecutionBridge:
    """Deterministic fixture bridge used by contract/integration tests."""

    def capabilities(self, profile: TargetProfile) -> CapabilityReport:
        return CapabilityReport(
            adapter="fixture",
            attacks=[{"id": "fixture", "available": True, "requirements": []}],
            drivers=[{"id": "fixture", "available": True}],
        )

    async def validate(
        self, profile: TargetProfile, attacks: list[str] | None = None
    ) -> ReadinessReport:
        return ReadinessReport(checks=[{"id": "fixture", "label": "fixture", "status": "ready"}])

    async def execute(
        self, run_spec: RunSpec, event_sink: EventSink, cancellation: CancellationToken
    ) -> EngineResult:
        await _maybe_emit(
            event_sink,
            EventRecord(
                type="operation.started",
                actor_id="attacker",
                session_id=f"fixture-{run_spec.run_id}",
                operation_id="fixture",
                data={"message": "<fixture>"},
            ),
        )
        if cancellation.is_set():
            return EngineResult(
                status="cancelled",
                raw={"fixture": True},
                summary={"verdict": "unknown"},
                replay_spec={**run_spec.resolved_manifest, "complete": True},
            )
        await _maybe_emit(
            event_sink,
            EventRecord(
                type="operation.completed",
                actor_id="attacker",
                session_id=f"fixture-{run_spec.run_id}",
                operation_id="fixture",
                data={"reply": "<fixture-response>", "html": "<b>escaped</b>"},
            ),
        )
        summary = {
            "verdict": "vulnerable",
            "check_status": "fail",
            "message": "Synthetic fixture only",
            "details": {"persisted": True, "leaked_in_vulnerable_mode": True},
            "synthetic": True,
        }
        return EngineResult(
            status="completed",
            raw={"fixture": True, "verdict": "fail"},
            summary=summary,
            replay_spec={
                **run_spec.resolved_manifest,
                "complete": True,
                "resolved_inputs": {"message": "fixture payload"},
            },
            finding={
                "id": f"{run_spec.run_id}-finding",
                "engine_verdict": "fail",
                "confidence": "proven",
                "stage_results": summary["details"],
                "evidence_ids": [],
                "raw_engine_payload": summary,
            },
        )

    def replay_support(self, saved_run: dict[str, Any]) -> ReplaySupport:
        return ReplaySupport(True, True, "Exact fixture-input rerun")


async def _maybe_emit(sink: EventSink, record: EventRecord) -> None:
    outcome = sink(record)
    if inspect.isawaitable(outcome):
        await outcome
