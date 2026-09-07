from __future__ import annotations

from alembic import op
from sqlalchemy import inspect, text

revision = "0002_source_sha"
down_revision = "0001_console"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    for table in ("runs", "replay_specs"):
        columns = {column["name"] for column in inspect(connection).get_columns(table)}
        if "source_sha" not in columns:
            op.execute(
                text(
                    f"ALTER TABLE {table} ADD COLUMN source_sha VARCHAR(160) "
                    "NOT NULL DEFAULT 'unknown'"
                )
            )


def downgrade() -> None:
    connection = op.get_bind()
    for table in ("replay_specs", "runs"):
        columns = {column["name"] for column in inspect(connection).get_columns(table)}
        if "source_sha" in columns:
            op.drop_column(table, "source_sha")
