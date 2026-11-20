from alembic import op

from database.schema import ACCOUNT_TABLES, apply_revision

revision = '0002_accounts'
down_revision = '0001_enterprise'
branch_labels = None
depends_on = None

def upgrade():
    apply_revision(op.get_bind(), 2, ACCOUNT_TABLES)

def downgrade():
    raise RuntimeError('Restore a database snapshot to roll back this migration')
