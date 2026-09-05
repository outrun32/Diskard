from __future__ import annotations

from alembic import op

from diskard.console.repository import metadata

revision = "0001_console"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(op.get_bind())


def downgrade() -> None:
    metadata.drop_all(op.get_bind())
