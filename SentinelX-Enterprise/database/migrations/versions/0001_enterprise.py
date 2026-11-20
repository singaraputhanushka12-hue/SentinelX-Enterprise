from alembic import op

from database.schema import TABLES, apply_revision

revision = '0001_enterprise'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    apply_revision(op.get_bind(), 1, TABLES)

def downgrade():
    raise RuntimeError('Restore a database snapshot to roll back this initial migration')

