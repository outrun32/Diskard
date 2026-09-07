from __future__ import annotations

from alembic import op
from sqlalchemy import inspect, text

revision = "0003_event_sequence_constraint"
down_revision = "0002_source_sha"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    constraints = {item["name"] for item in inspect(connection).get_unique_constraints("events")}
    if "uq_events_run_sequence" not in constraints:
        op.execute(
            text(
                "ALTER TABLE events ADD CONSTRAINT uq_events_run_sequence UNIQUE (run_id, sequence)"
            )
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        constraints = {
            item["name"] for item in inspect(connection).get_unique_constraints("events")
        }
        if "uq_events_run_sequence" in constraints:
            op.drop_constraint("uq_events_run_sequence", "events", type_="unique")
