"""Frozen initial console schema; later changes belong in new revisions."""

from alembic import op
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
)

revision = "0001_console"
down_revision = None
branch_labels = None
depends_on = None

metadata = MetaData()

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


def upgrade() -> None:
    metadata.create_all(op.get_bind())


def downgrade() -> None:
    metadata.drop_all(op.get_bind())
