from alembic import op

from database.schema import AI_REPORT_TABLES, apply_revision

revision = '0004_ai_reports'
down_revision = '0003_intelligence'
branch_labels = None
depends_on = None

def upgrade():
    apply_revision(op.get_bind(), 4, AI_REPORT_TABLES)

def downgrade():
    raise RuntimeError('Restore a database snapshot to roll back this migration')
