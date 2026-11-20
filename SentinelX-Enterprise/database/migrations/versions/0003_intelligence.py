from alembic import op

from database.schema import INTELLIGENCE_TABLES, apply_revision

revision = '0003_intelligence'
down_revision = '0002_accounts'
branch_labels = None
depends_on = None

def upgrade():
    apply_revision(op.get_bind(), 3, INTELLIGENCE_TABLES)

def downgrade():
    raise RuntimeError('Restore a database snapshot to roll back this migration')
