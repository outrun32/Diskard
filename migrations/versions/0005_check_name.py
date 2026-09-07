"""Add user-visible names to full attacks."""

import sqlalchemy as sa
from alembic import op

revision = "0005_check_name"
down_revision = "0004_checks"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("checks", sa.Column("name", sa.String(160), nullable=True))


def downgrade():
    op.drop_column("checks", "name")
