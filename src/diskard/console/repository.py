"""PostgreSQL repository for profiles, runs, durable events and evidence."""

from __future__ import annotations

import hashlib
import json
import threading
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from diskard.console.contracts import EventRecord, RunStatus, TargetProfile
from diskard.console.redaction import digest, redact

try:
    from sqlalchemy import (
        JSON,
        Boolean,
        Column,
        DateTime,
        Integer,
        MetaData,
        String,
        Table,
        Text,
        UniqueConstraint,
        and_,
        create_engine,
        desc,
        func,
        insert,
        inspect,
        select,
        text,
        update,
    )
    from sqlalchemy.engine import Connection, Engine
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "The durable console needs SQLAlchemy. Install diskard[console] or diskard[dev]."
    ) from exc

SCHEMA_VERSION = 4
metadata = MetaData()

checks = Table(
    "checks",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("submission_id", String(128), nullable=False, unique=True),
    Column("request_digest", String(64), nullable=False),
    Column("profile_id", String(80), nullable=False),
    Column("profile_version", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("attacks", JSON, nullable=False),
    Column("run_ids", JSON, nullable=False),
)

target_profiles = Table(
    "target_profiles",
    metadata,
    Column("id", String(80), primary_key=True),
    Column("name", String(160), nullable=False),
    Column("adapter", String(120), nullable=False),
    Column("version", Integer, nullable=False, default=1),
    Column("config", JSON, nullable=False),
    Column("credential_refs", JSON, nullable=False),
    Column("config_digest", String(64), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

runs = Table(
    "runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("parent_run_id", String(64), nullable=True),
    Column("mode", String(32), nullable=False),
    Column("origin", String(32), nullable=False, default="console"),
    Column("target_profile_id", String(80), nullable=False),
    Column("target_profile_version", Integer, nullable=False),
    Column("status", String(20), nullable=False),
    Column("submitted_at", DateTime(timezone=True), nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=True),
    Column("finished_at", DateTime(timezone=True), nullable=True),
    Column("config_snapshot", JSON, nullable=False),
    Column("config_digest", String(64), nullable=False),
    Column("engine_version", String(160), nullable=False),
    Column("source_sha", String(160), nullable=False, default="unknown"),
    Column("scenario_version", String(160), nullable=False),
    Column("scenario_hash", String(64), nullable=True),
    Column("raw_engine_result", JSON, nullable=True),
    Column("summary", JSON, nullable=True),
    Column("error", Text, nullable=True),
    Column("isolation_status", JSON, nullable=False),
    Column("last_event_sequence", Integer, nullable=False, default=0),
    Column("client_submission_id", String(128), nullable=True, unique=True),
)

run_units = Table(
    "run_units",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(64), nullable=False),
    Column("scenario_id", String(160), nullable=True),
    Column("phase", String(40), nullable=True),
    Column("attempt_index", Integer, nullable=True),
    Column("status", String(20), nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=True),
    Column("finished_at", DateTime(timezone=True), nullable=True),
    Column("raw", JSON, nullable=False),
)

events = Table(
    "events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(64), nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("unit_id", String(64), nullable=True),
    Column("operation_id", String(160), nullable=True),
    Column("parent_event_id", String(64), nullable=True),
    Column("source_timestamp", DateTime(timezone=True), nullable=True),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("type", String(64), nullable=False),
    Column("actor_id", String(160), nullable=True),
    Column("session_id", String(160), nullable=True),
    Column("source", String(64), nullable=False),
    Column("data", JSON, nullable=False),
    Column("data_digest", String(64), nullable=False),
    Column("truncated", Boolean, nullable=False, default=False),
    Column("artifact_available", Boolean, nullable=False, default=False),
    UniqueConstraint("run_id", "sequence", name="uq_events_run_sequence"),
)

event_artifacts = Table(
    "event_artifacts",
    metadata,
    Column("event_id", String(64), primary_key=True),
    Column("content", Text, nullable=False),
    Column("content_digest", String(64), nullable=False),
)

findings = Table(
    "findings",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(64), nullable=False),
    Column("engine_verdict", String(80), nullable=True),
    Column("confidence", String(40), nullable=True),
    Column("stage_results", JSON, nullable=False),
    Column("evidence_ids", JSON, nullable=False),
    Column("raw_engine_payload", JSON, nullable=False),
)

replay_specs = Table(
    "replay_specs",
    metadata,
    Column("run_id", String(64), primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("resolved_inputs", JSON, nullable=False),
    Column("driver", String(80), nullable=False),
    Column("scenario_version", String(160), nullable=True),
    Column("payload", JSON, nullable=False),
    Column("parameters", JSON, nullable=False),
    Column("credential_refs", JSON, nullable=False),
    Column("state_requirements", JSON, nullable=False),
    Column("complete", Boolean, nullable=False),
    Column("unsupported_reasons", JSON, nullable=False),
    Column("source_sha", String(160), nullable=False, default="unknown"),
)

schema_versions = Table(
    "console_schema_versions",
    metadata,
    Column("version", Integer, primary_key=True),
    Column("applied_at", DateTime(timezone=True), nullable=False),
)

_local_locks: dict[str, threading.Lock] = {}


def make_engine(database_url: str) -> Engine:
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    kwargs: dict[str, Any] = {"future": True, "pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(database_url, **kwargs)


def migrate(engine: Engine) -> None:
    """Run the same Alembic revisions at startup and from the migration CLI."""
    from alembic import command
    from alembic.config import Config

    config = Config()
    config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[3] / "migrations")
    )
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            connection.execute(text("SELECT pg_advisory_xact_lock(8941234)"))
        if "console_schema_versions" in inspect(connection).get_table_names():
            current = connection.execute(select(func.max(schema_versions.c.version))).scalar_one()
            if current is not None and current > SCHEMA_VERSION:
                raise RuntimeError("database schema is newer than this build")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def _now() -> datetime:
    return datetime.now(UTC)


def _row(row: Any) -> dict[str, Any] | None:
    return dict(row._mapping) if row is not None else None


class ExecutorBusy(RuntimeError):
    pass


class ExecutorLease:
    def __init__(self, connection: Connection, local_lock: threading.Lock | None = None) -> None:
        self.connection = connection
        self.local_lock = local_lock

    def check(self) -> None:
        # Never reconnect this session: a replacement connection would not own the lock.
        if self.connection.closed or self.connection.invalidated:
            raise ExecutorBusy("executor ownership connection was lost")
        self.connection.execute(text("SELECT 1"))

    def release(self) -> None:
        try:
            if self.connection.dialect.name == "postgresql":
                self.connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": 8_941_233})
        finally:
            self.connection.close()
            if self.local_lock is not None:
                self.local_lock.release()


class RunStore:
    def __init__(self, engine: Engine, *, event_max_bytes: int = 262_144) -> None:
        self.engine = engine
        self.event_max_bytes = event_max_bytes

    def ping(self) -> None:
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    def acquire_executor(self) -> ExecutorLease:
        if self.engine.dialect.name != "postgresql":
            lock = _local_locks.setdefault(str(self.engine.url), threading.Lock())
            if not lock.acquire(blocking=False):
                raise ExecutorBusy("another console executor owns this database")
            return ExecutorLease(self.engine.connect(), lock)
        connection = self.engine.connect()
        owned = connection.execute(
            text("SELECT pg_try_advisory_lock(:key)"), {"key": 8_941_233}
        ).scalar()
        if not owned:
            connection.close()
            raise ExecutorBusy("another console executor owns this database")
        return ExecutorLease(connection)

    def mark_orphans_interrupted(self) -> int:
        with self.engine.begin() as connection:
            result = connection.execute(
                update(runs)
                .where(runs.c.status.in_(["running", "cancelling"]))
                .values(
                    status="interrupted",
                    finished_at=_now(),
                    error="Executor restarted while this run was in flight",
                    isolation_status={"state": "unknown", "reason": "process restart"},
                )
            )
            return result.rowcount

    def profile(self, profile_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            return _row(
                connection.execute(
                    select(target_profiles).where(target_profiles.c.id == profile_id)
                ).first()
            )

    def profiles(self) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            return [
                _row(row)
                for row in connection.execute(
                    select(target_profiles).order_by(target_profiles.c.id)
                )
            ]

    def upsert_profile(self, profile: TargetProfile, *, explicit: bool = False) -> dict[str, Any]:
        config = redact(profile.model_dump(mode="json"))
        credential_refs = {
            role: {
                key: value
                for key, value in actor.model_dump(mode="json").items()
                if (key.endswith("_env") or key.endswith("_file")) and value is not None
            }
            for role, actor in profile.actors.items()
        }
        now = _now()
        profile_digest = digest(config)
        with self.engine.begin() as connection:
            if connection.dialect.name == "postgresql":
                connection.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                    {"key": "profile:" + profile.id},
                )
            current = _row(
                connection.execute(
                    select(target_profiles).where(target_profiles.c.id == profile.id)
                ).first()
            )
            if current is None:
                values = {
                    "id": profile.id,
                    "name": profile.name,
                    "adapter": profile.adapter,
                    "version": 1,
                    "config": config,
                    "credential_refs": credential_refs,
                    "config_digest": profile_digest,
                    "created_at": now,
                    "updated_at": now,
                }
                connection.execute(insert(target_profiles).values(**values))
                return values
            if current["config_digest"] == profile_digest:
                return current
            if not explicit:
                return {**current, "config_difference": True, "incoming_digest": profile_digest}
            version = int(current["version"]) + 1
            connection.execute(
                update(target_profiles)
                .where(target_profiles.c.id == profile.id)
                .values(
                    name=profile.name,
                    adapter=profile.adapter,
                    version=version,
                    config=config,
                    credential_refs=credential_refs,
                    config_digest=profile_digest,
                    updated_at=now,
                )
            )
            return {
                **current,
                "version": version,
                "config": config,
                "credential_refs": credential_refs,
                "config_digest": profile_digest,
                "name": profile.name,
                "adapter": profile.adapter,
                "updated_at": now,
            }

    def create_run(
        self,
        *,
        run_id: str,
        profile: dict[str, Any],
        mode: str,
        origin: str,
        attack: str,
        driver: str,
        options: dict[str, Any],
        source_sha: str = "unknown",
        parent_run_id: str | None = None,
        client_submission_id: str | None = None,
        replay_spec: dict[str, Any] | None = None,
        connection: Connection | None = None,
    ) -> dict[str, Any]:
        snapshot = redact(
            {
                "attack": attack,
                "driver": driver,
                "options": options,
                "profile": profile.get("config", profile),
            }
        )
        values = {
            "id": run_id,
            "parent_run_id": parent_run_id,
            "mode": mode,
            "origin": origin,
            "target_profile_id": profile["id"],
            "target_profile_version": profile["version"],
            "status": "queued",
            "submitted_at": _now(),
            "config_snapshot": snapshot,
            "config_digest": digest(snapshot),
            "engine_version": "diskard-0.1.0",
            "source_sha": source_sha,
            "scenario_version": attack,
            "scenario_hash": digest({"attack": attack, "driver": driver}),
            "isolation_status": {
                "state": "installation-scoped",
                "target_reset": "adapter-dependent",
            },
            "last_event_sequence": 0,
            "client_submission_id": client_submission_id,
        }
        with (
            nullcontext(connection) if connection is not None else self.engine.begin()
        ) as connection:
            if client_submission_id:
                if connection.dialect.name == "postgresql":
                    connection.execute(
                        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                        {"key": "submission:" + client_submission_id},
                    )
                existing = _row(
                    connection.execute(
                        select(runs).where(runs.c.client_submission_id == client_submission_id)
                    ).first()
                )
                if existing is not None:
                    if (
                        existing["config_digest"] != values["config_digest"]
                        or existing["parent_run_id"] != parent_run_id
                    ):
                        raise ValueError("submission_id was already used for a different request")
                    return existing
            connection.execute(insert(runs).values(**values))
            if replay_spec is not None:
                self._insert_replay(connection, run_id, replay_spec)
        return values

    def create_check(
        self,
        *,
        profile: dict[str, Any],
        attacks: list[str],
        driver: str,
        submission_id: str,
        source_sha: str,
    ) -> dict[str, Any]:
        request_digest = digest({"profile": profile["id"], "attacks": attacks, "driver": driver})
        with self.engine.begin() as connection:
            if connection.dialect.name == "postgresql":
                connection.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                    {"key": "check:" + submission_id},
                )
            existing = _row(
                connection.execute(
                    select(checks).where(checks.c.submission_id == submission_id)
                ).first()
            )
            if existing:
                if existing["request_digest"] != request_digest:
                    raise ValueError("submission_id was already used for another check")
                return existing
            check_id = uuid4().hex
            run_ids = []
            for attack in attacks:
                run_id = uuid4().hex
                self.create_run(
                    run_id=run_id,
                    profile=profile,
                    mode="experiment",
                    origin="console-check",
                    attack=attack,
                    driver=driver,
                    options={"budget": 1, "repeat": 1, "check_id": check_id},
                    source_sha=source_sha,
                    connection=connection,
                )
                run_ids.append(run_id)
            row = {
                "id": check_id,
                "submission_id": submission_id,
                "request_digest": request_digest,
                "profile_id": profile["id"],
                "profile_version": profile["version"],
                "created_at": _now(),
                "attacks": attacks,
                "run_ids": run_ids,
            }
            connection.execute(insert(checks).values(**row))
        return row

    def check(self, check_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = _row(connection.execute(select(checks).where(checks.c.id == check_id)).first())
        if row is None:
            return None
        children = [self.run(run_id, include_events=False) for run_id in row["run_ids"]]
        return {**row, "runs": children}

    def _replay_values(self, run_id: str, spec: dict[str, Any]) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "schema_version": spec.get("schema_version", 1),
            "resolved_inputs": redact(spec.get("resolved_inputs", {})),
            "driver": spec.get("driver", "template"),
            "scenario_version": spec.get("scenario_version"),
            "payload": redact(spec.get("payload", {})),
            "parameters": redact(spec.get("parameters", {})),
            "credential_refs": redact(spec.get("credential_refs", {})),
            "state_requirements": redact(spec.get("state_requirements", {})),
            "complete": bool(spec.get("complete", False)),
            "unsupported_reasons": redact(spec.get("unsupported_reasons", [])),
            "source_sha": spec.get("source_sha", "unknown"),
        }

    def _insert_replay(self, connection: Connection, run_id: str, spec: dict[str, Any]) -> None:
        connection.execute(insert(replay_specs).values(**self._replay_values(run_id, spec)))

    def save_replay(self, run_id: str, spec: dict[str, Any]) -> None:
        """Persist resolved inputs before the bridge makes its first target call."""
        with self.engine.begin() as connection:
            connection.execute(
                select(runs.c.id).where(runs.c.id == run_id).with_for_update()
            ).scalar_one()
            changed = connection.execute(
                update(replay_specs)
                .where(replay_specs.c.run_id == run_id)
                .values(**self._replay_values(run_id, spec))
            )
            if not changed.rowcount:
                self._insert_replay(connection, run_id, spec)

    def run(self, run_id: str, *, include_events: bool = True) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            result = _row(connection.execute(select(runs).where(runs.c.id == run_id)).first())
            if result is None:
                return None
            result["finding"] = _row(
                connection.execute(select(findings).where(findings.c.run_id == run_id)).first()
            )
            result["replay_spec"] = _row(
                connection.execute(
                    select(replay_specs).where(replay_specs.c.run_id == run_id)
                ).first()
            )
            if include_events:
                result["events"] = self._events(connection, run_id)
            return result

    def overview(self) -> dict[str, Any]:
        """Aggregate the whole history, excluding explicit synthetic executions."""
        real = and_(
            runs.c.origin.notin_(["test", "demo"]),
            func.coalesce(runs.c.summary["synthetic"].as_boolean(), False) == False,  # noqa: E712
        )
        verdict = runs.c.summary["verdict"].as_string()
        with self.engine.connect() as connection:
            recent_checks = [
                _row(row)
                for row in connection.execute(
                    select(checks).order_by(desc(checks.c.created_at)).limit(6)
                )
            ]
            groups = connection.execute(
                select(runs.c.status, verdict, func.count())
                .where(real)
                .group_by(runs.c.status, verdict)
            ).all()
            total = connection.execute(select(func.count()).select_from(runs)).scalar_one()
            targets = connection.execute(
                select(func.count()).select_from(target_profiles)
            ).scalar_one()
            active = [
                _row(row)
                for row in connection.execute(
                    select(runs)
                    .where(real, runs.c.status.in_(["queued", "running", "cancelling"]))
                    .order_by(desc(runs.c.submitted_at))
                    .limit(6)
                )
            ]
        counts = {"runs": 0, "active": 0, "findings": 0, "errors": 0, "unknown": 0}
        for status, outcome, count in groups:
            counts["runs"] += count
            counts["active"] += count if status in {"queued", "running", "cancelling"} else 0
            counts["findings"] += count if outcome in {"vulnerable", "fail"} else 0
            counts["errors"] += count if status in {"failed", "interrupted"} else 0
            counts["unknown"] += (
                count
                if status not in {"queued", "running", "cancelling"}
                and outcome not in {"vulnerable", "fail", "clean", "pass"}
                else 0
            )
        recent, _ = self.list_runs(limit=8)
        return {
            "checks": recent_checks,
            "counts": counts,
            "targets": targets,
            "synthetic_runs": total - counts["runs"],
            "active": active,
            "recent": recent,
        }

    def list_runs(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        target_id: str | None = None,
        status: str | None = None,
        attack: str | None = None,
        parent_run_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses = []
        if target_id:
            clauses.append(runs.c.target_profile_id == target_id)
        if status:
            clauses.append(runs.c.status == status)
        if attack:
            clauses.append(runs.c.scenario_version == attack)
        if parent_run_id:
            clauses.append(runs.c.parent_run_id == parent_run_id)
        with self.engine.connect() as connection:
            query = select(runs).order_by(desc(runs.c.submitted_at)).limit(limit).offset(offset)
            count_query = select(func.count()).select_from(runs)
            if clauses:
                query = query.where(and_(*clauses))
                count_query = count_query.where(and_(*clauses))
            return (
                [_row(row) for row in connection.execute(query)],
                int(connection.execute(count_query).scalar_one()),
            )

    def claim_next_run(self) -> dict[str, Any] | None:
        with self.engine.begin() as connection:
            query = (
                select(runs).where(runs.c.status == "queued").order_by(runs.c.submitted_at).limit(1)
            )
            if connection.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            selected = _row(connection.execute(query).first())
            if selected is None:
                return None
            claimed = connection.execute(
                update(runs)
                .where(and_(runs.c.id == selected["id"], runs.c.status == "queued"))
                .values(status="running", started_at=_now())
            )
            if claimed.rowcount == 0:
                return None
            selected["status"] = "running"
            selected["started_at"] = _now()
            return selected

    def transition(self, run_id: str, status: RunStatus, *, error: str | None = None) -> None:
        allowed = {
            "queued": {"running", "cancelled", "interrupted"},
            "running": {"cancelling", "completed", "failed", "cancelled", "interrupted"},
            "cancelling": {"cancelled", "failed", "interrupted"},
        }
        with self.engine.begin() as connection:
            current = connection.execute(
                select(runs.c.status).where(runs.c.id == run_id).with_for_update()
            ).scalar_one_or_none()
            if current is None:
                raise KeyError(run_id)
            if current == status:
                return
            if status != current and status not in allowed.get(current, set()):
                raise ValueError(f"invalid run transition {current} -> {status}")
            values: dict[str, Any] = {"status": status}
            if error is not None:
                values["error"] = redact(error)
            if status in {"completed", "failed", "cancelled", "interrupted"}:
                values["finished_at"] = _now()
            connection.execute(update(runs).where(runs.c.id == run_id).values(**values))

    def request_cancel(self, run_id: str) -> dict[str, Any] | None:
        with self.engine.begin() as connection:
            current = _row(
                connection.execute(
                    select(runs).where(runs.c.id == run_id).with_for_update()
                ).first()
            )
            if current is None:
                return None
            status = current["status"]
            if status == "queued":
                next_status = "cancelled"
                connection.execute(
                    update(runs)
                    .where(runs.c.id == run_id)
                    .values(status=next_status, finished_at=_now())
                )
            elif status == "running":
                next_status = "cancelling"
                connection.execute(
                    update(runs).where(runs.c.id == run_id).values(status=next_status)
                )
            else:
                next_status = status
            return {**current, "status": next_status}

    def append_event(
        self,
        run_id: str,
        record: EventRecord,
        *,
        secret_values: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        data = redact(record.data, secret_values)
        serialized = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
        full_digest = hashlib.sha256(serialized.encode()).hexdigest()
        truncated = len(serialized.encode()) > self.event_max_bytes
        event_id = uuid4().hex
        with self.engine.begin() as connection:
            sequence = connection.execute(
                update(runs)
                .where(runs.c.id == run_id, runs.c.status.in_(["queued", "running", "cancelling"]))
                .values(last_event_sequence=runs.c.last_event_sequence + 1)
                .returning(runs.c.last_event_sequence)
            ).scalar_one_or_none()
            if sequence is None:
                raise ValueError("cannot append events to a missing or terminal run")
            stored_data: object = data
            if truncated:
                preview = serialized.encode()[: self.event_max_bytes].decode("utf-8", "ignore")
                stored_data = {"preview": preview, "truncated": True}
            connection.execute(
                insert(events).values(
                    id=event_id,
                    run_id=run_id,
                    sequence=sequence,
                    unit_id=record.unit_id,
                    operation_id=record.operation_id,
                    parent_event_id=record.parent_event_id,
                    source_timestamp=record.source_timestamp,
                    observed_at=_now(),
                    type=record.type,
                    actor_id=record.actor_id,
                    session_id=record.session_id,
                    source=record.source,
                    data=stored_data,
                    data_digest=full_digest,
                    truncated=truncated,
                    artifact_available=truncated,
                )
            )
            if truncated:
                connection.execute(
                    insert(event_artifacts).values(
                        event_id=event_id, content=serialized, content_digest=full_digest
                    )
                )
        return {
            "id": event_id,
            "sequence": sequence,
            "type": record.type,
            "data": stored_data,
            "truncated": truncated,
        }

    def events_page(self, run_id: str, *, after: int = 0, limit: int = 100) -> dict[str, Any]:
        with self.engine.connect() as connection:
            items = self._events(connection, run_id, after=after, limit=limit)
            last = connection.execute(
                select(runs.c.last_event_sequence).where(runs.c.id == run_id)
            ).scalar_one_or_none()
            return {
                "items": items,
                "after": after,
                "limit": limit,
                "last_event_sequence": last or 0,
            }

    def _events(
        self,
        connection: Connection,
        run_id: str,
        *,
        after: int = 0,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        query = (
            select(events)
            .where(and_(events.c.run_id == run_id, events.c.sequence > after))
            .order_by(events.c.sequence)
        )
        if limit is not None:
            query = query.limit(limit)
        result = [_row(item) for item in connection.execute(query)]
        for item in result:
            if not item["artifact_available"]:
                continue
            artifact = _row(
                connection.execute(
                    select(event_artifacts).where(event_artifacts.c.event_id == item["id"])
                ).first()
            )
            if artifact:
                item["artifact"] = artifact["content"]
        return result

    def finalize(
        self,
        run_id: str,
        *,
        status: RunStatus,
        raw_engine_result: dict[str, Any],
        summary: dict[str, Any],
        replay_spec: dict[str, Any],
        error: str | None = None,
        isolation_status: dict[str, Any] | None = None,
        finding: dict[str, Any] | None = None,
    ) -> None:
        with self.engine.begin() as connection:
            current = connection.execute(
                select(runs.c.status).where(runs.c.id == run_id).with_for_update()
            ).scalar_one()
            if current in {"completed", "failed", "cancelled", "interrupted"}:
                raise ValueError(f"run {run_id} already finalized as {current}")
            if status not in {"completed", "failed", "cancelled", "interrupted"}:
                raise ValueError("finalize requires a terminal status")
            if current == "cancelling":
                status = "cancelled"
            connection.execute(
                update(runs)
                .where(runs.c.id == run_id)
                .values(
                    status=status,
                    finished_at=_now(),
                    raw_engine_result=redact(raw_engine_result),
                    summary=redact(summary),
                    error=redact(error) if error else None,
                    isolation_status=redact(isolation_status or {}),
                )
            )
            existing_replay = connection.execute(
                select(replay_specs.c.run_id).where(replay_specs.c.run_id == run_id)
            ).scalar_one_or_none()
            if existing_replay is None:
                connection.execute(
                    insert(replay_specs).values(**self._replay_values(run_id, replay_spec))
                )
            else:
                connection.execute(
                    update(replay_specs)
                    .where(replay_specs.c.run_id == run_id)
                    .values(**self._replay_values(run_id, replay_spec))
                )
            if finding is not None:
                existing_finding = connection.execute(
                    select(findings.c.id).where(findings.c.run_id == run_id)
                ).scalar_one_or_none()
                if existing_finding is None:
                    connection.execute(
                        insert(findings).values(
                            id=finding.get("id", uuid4().hex),
                            run_id=run_id,
                            engine_verdict=finding.get("engine_verdict"),
                            confidence=finding.get("confidence"),
                            stage_results=redact(finding.get("stage_results", {})),
                            evidence_ids=redact(finding.get("evidence_ids", [])),
                            raw_engine_payload=redact(finding.get("raw_engine_payload", finding)),
                        )
                    )

    def import_legacy(self, source_path: Path) -> str:
        raw_bytes = source_path.read_bytes()
        source_digest = hashlib.sha256(raw_bytes).hexdigest()
        run_id = f"import-{source_digest[:20]}"
        if self.run(run_id) is not None:
            return run_id
        payload = json.loads(raw_bytes)
        attack = str(payload.get("attack") or payload.get("scenario") or "legacy-record")
        snapshot = redact({"source": source_path.name, "payload": payload})
        now = _now()
        with self.engine.begin() as connection:
            profile_exists = connection.execute(
                select(target_profiles.c.id).where(target_profiles.c.id == "legacy-import")
            ).scalar_one_or_none()
            if profile_exists is None:
                profile_config = {
                    "name": "Legacy imported record",
                    "adapter": "unknown",
                    "base_url": "",
                }
                connection.execute(
                    insert(target_profiles).values(
                        id="legacy-import",
                        name="Legacy imported record",
                        adapter="unknown",
                        version=1,
                        config=profile_config,
                        credential_refs={},
                        config_digest=digest(profile_config),
                        created_at=now,
                        updated_at=now,
                    )
                )
            connection.execute(
                insert(runs).values(
                    id=run_id,
                    parent_run_id=None,
                    mode="legacy-import",
                    origin="cli-import",
                    target_profile_id="legacy-import",
                    target_profile_version=1,
                    status="imported",
                    submitted_at=now,
                    started_at=None,
                    finished_at=None,
                    config_snapshot=snapshot,
                    config_digest=source_digest,
                    engine_version="legacy",
                    source_sha="legacy-import",
                    scenario_version=attack,
                    scenario_hash=None,
                    raw_engine_result=snapshot,
                    summary={
                        "imported": True,
                        "source": source_path.name,
                        "source_digest": source_digest,
                        "verdict": payload.get("status")
                        if payload.get("status") in {"vulnerable", "clean", "fail", "pass"}
                        else "unknown",
                        "missing_fields": ["trace", "replay_inputs", "execution_timestamps"],
                    },
                    error=None,
                    isolation_status={"state": "not-applicable", "imported": True},
                    last_event_sequence=1,
                    client_submission_id=f"legacy:{source_digest}",
                )
            )
            connection.execute(
                insert(events).values(
                    id=uuid4().hex,
                    run_id=run_id,
                    sequence=1,
                    type="legacy_import",
                    source="legacy",
                    observed_at=now,
                    source_timestamp=None,
                    data=snapshot,
                    data_digest=source_digest,
                    truncated=False,
                    artifact_available=False,
                )
            )
        return run_id

    def compare(self, left_id: str, right_id: str) -> dict[str, Any] | None:
        left = self.run(left_id)
        right = self.run(right_id)
        if left is None or right is None:
            return None
        left_config = left.get("config_snapshot") or {}
        right_config = right.get("config_snapshot") or {}
        keys = sorted(set(left_config) | set(right_config))
        return {
            "left": left,
            "right": right,
            "configuration_differences": [
                {
                    "key": key,
                    "left": left_config.get(key),
                    "right": right_config.get(key),
                }
                for key in keys
                if left_config.get(key) != right_config.get(key)
            ],
            "statistical_claim": (
                "not available: comparison is descriptive, not a cohort estimate"
            ),
        }
