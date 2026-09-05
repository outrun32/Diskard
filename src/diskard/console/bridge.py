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
from diskard.report import confidence_for


class CancellationToken(Protocol):
    def is_set(self) -> bool: ...


EventSink = Callable[[EventRecord], Awaitable[None] | None]


class ExecutionBridge(Protocol):
    def capabilities(self, profile: TargetProfile) -> CapabilityReport: ...

    async def validate(self, profile: TargetProfile) -> ReadinessReport: ...

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
    if not any(requested.is_relative_to(root) for root in secret_roots):
        raise BridgeError("credential_file must be under /run/secrets or /config/secrets")
    return requested.read_text(encoding="utf-8").strip()


def _url_is_supported(base_url: str) -> bool:
    return "/models/chat/completions" not in base_url


def _suite_status(suite_result: Any) -> str:
    status = getattr(suite_result, "status", None)
    if status is not None:
        return str(getattr(status, "value", status))
    for scenario_result in suite_result.results:
        for step in scenario_result.steps:
            if step.error is not None:
                return "error"
            for check in step.results:
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
                    "Use the legacy live endpoint for the existing search driver; "
                    "durable exact-input search is not yet exposed by the bridge"
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

    async def validate(self, profile: TargetProfile) -> ReadinessReport:
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
                response = await client.get(profile.base_url)
            checks.append(
                {
                    "id": "target_api",
                    "label": "target API",
                    "status": "ready" if 200 <= response.status_code < 400 else "blocked",
                    "detail": f"HTTP {response.status_code}",
                    "reason": None
                    if 200 <= response.status_code < 400
                    else "expected a reachable HTTP endpoint",
                }
            )
        except Exception as exc:  # noqa: BLE001
            checks.append(
                {"id": "target_api", "label": "target API", "status": "blocked", "reason": str(exc)}
            )

        required_roles = {"attacker", "trigger_user", "data_subject"}
        if "delayed-recommendation-manipulation" in KNOWN_ATTACKS:
            required_roles.add("control")
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
            configured = bool(actor.credential_env and os.getenv(actor.credential_env)) or bool(
                actor.credential_file
            )
            checks.append(
                {
                    "id": f"actor:{role}",
                    "label": f"{role} credentials",
                    "status": "ready" if configured else "blocked",
                    "detail": actor.credential_env or actor.credential_file or "not configured",
                    "reason": None
                    if configured
                    else "set the referenced env variable or mounted secret file",
                }
            )

        mongo_ref = profile.adapter_options.get("mongo_uri_env")
        mongo_configured = bool(mongo_ref and os.getenv(str(mongo_ref)))
        checks.append(
            {
                "id": "evidence:mongo",
                "label": "Mongo evidence collector",
                "status": "ready" if mongo_configured else "blocked",
                "detail": mongo_ref or "missing mongo_uri_env",
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
                "status": "ready" if invest_url else "blocked",
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

    def _actors(self, profile: TargetProfile, *, required_roles: set[str]) -> dict[str, Any]:
        from diskard.models import Actor

        result: dict[str, Actor] = {}
        for role in required_roles:
            spec = profile.actors.get(role)
            if spec is None:
                raise BridgeError(f"profile is missing actor role {role!r}")
            api_key = _read_ref(
                spec.credential_env,
                spec.credential_file,
                secret_roots=self.secret_roots,
            )
            if not api_key:
                raise BridgeError(f"credential reference for actor role {role!r} is not configured")
            access_token = _read_ref(
                spec.access_token_env,
                spec.access_token_file,
                secret_roots=self.secret_roots,
            )
            result[role] = Actor(cus=spec.cus, api_key=api_key, access_token=access_token)
        return result

    async def execute(
        self, run_spec: RunSpec, event_sink: EventSink, cancellation: CancellationToken
    ) -> EngineResult:
        from types import SimpleNamespace

        from giskard.checks import Suite

        from diskard.adapters.investment_stand import (
            InvestServerEvidence,
            MongoEvidence,
            SemanticMemoryEvidence,
            StandClient,
        )
        from diskard.cli import _build_scenario
        from diskard.runner import make_dispatch

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
        if run_spec.attack != "cross-user-direct-memory-leak":
            required.add("data_subject")
        if run_spec.attack == "delayed-recommendation-manipulation":
            required.add("control")
        actors = self._actors(run_spec.profile, required_roles=required)
        secret_values = tuple(actor.api_key for actor in actors.values())
        config = run_spec.profile
        mongo_ref = config.adapter_options.get("mongo_uri_env")
        mongo_uri = os.getenv(str(mongo_ref)) if mongo_ref else None
        if not mongo_uri:
            raise BridgeError("Mongo evidence collector is not configured")
        invest_url = str(config.adapter_options.get("invest_url", ""))
        if not invest_url:
            raise BridgeError("adapter_options.invest_url is required")
        stand = StandClient(config.base_url)
        mongo = MongoEvidence(mongo_uri=mongo_uri)
        invest = InvestServerEvidence(base_url=invest_url)
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
            operation_data = {
                "label": inputs.label,
                "phase": inputs.phase,
                "message": inputs.message,
                "auth_mode": inputs.auth_mode,
            }
            await emit(
                EventRecord(
                    type="operation.started",
                    actor_id=inputs.actor_cus,
                    session_id=inputs.session_id,
                    operation_id=inputs.label,
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
                        actor_id=inputs.actor_cus,
                        session_id=inputs.session_id,
                        operation_id=inputs.label,
                        data=redact({"error": str(exc), **operation_data}, secret_values),
                        source_timestamp=datetime.now(UTC),
                    )
                )
                raise
            await emit(
                EventRecord(
                    type="operation.completed",
                    actor_id=inputs.actor_cus,
                    session_id=inputs.session_id,
                    operation_id=inputs.label,
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
        )
        scenario, cleanup_key = _build_scenario(args, wrapped_dispatch, run_spec.run_id)
        replay_spec = {
            **run_spec.resolved_manifest,
            "scenario_version": run_spec.attack,
            "complete": False,
            "unsupported_reasons": [
                "current scenario builders generate per-run secrets/session IDs internally",
                "target state restoration is adapter-dependent and not configured",
            ],
        }
        try:
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
                error = step.error.summary()
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
            summary = {
                "scenario": scenario.name,
                "check_status": check_status,
                "message": check_result.message,
                "details": details,
                "verdict": "vulnerable" if check_status == "fail" else "clean",
            }
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
                    "stage_results": details,
                    "evidence_ids": [],
                    "raw_engine_payload": {"message": check_result.message, "details": details},
                }
            return EngineResult(
                status="cancelled" if cancellation.is_set() else "completed",
                raw={
                    "suite_status": _suite_status(suite_result),
                    "check_status": check_status,
                    "message": check_result.message,
                    "details": details,
                },
                summary=summary,
                replay_spec=replay_spec,
                finding=finding,
                isolation_status={
                    "state": "cleanup-attempted",
                    "target_reset": "session-scoped cleanup only",
                    "limitation": "another process can mutate the same target",
                },
            )
        finally:
            if cleanup_key is not None:
                await asyncio.to_thread(mongo.delete_by_source_session, cleanup_key)
            await asyncio.to_thread(semantic.delete_by_user, role_cus["attacker"])
            await stand.aclose()
            await invest.aclose()

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

    async def validate(self, profile: TargetProfile) -> ReadinessReport:
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
