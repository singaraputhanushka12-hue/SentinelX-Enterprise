from alembic import op

from database.schema import AI_SESSION_TABLES, apply_revision

revision = '0005_ai_sessions'
down_revision = '0004_ai_reports'
branch_labels = None
depends_on = None


def upgrade():
    apply_revision(op.get_bind(), 5, AI_SESSION_TABLES)


def downgrade():
    raise RuntimeError('Restore a database snapshot to roll back this migration')
