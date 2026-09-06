"""Durable groups of existing scenario runs."""

import sqlalchemy as sa
from alembic import op

revision = "0004_checks"
down_revision = "0003_event_sequence_constraint"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "checks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("submission_id", sa.String(128), nullable=False, unique=True),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("profile_id", sa.String(80), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attacks", sa.JSON(), nullable=False),
        sa.Column("run_ids", sa.JSON(), nullable=False),
    )


def downgrade():
    op.drop_table("checks")
