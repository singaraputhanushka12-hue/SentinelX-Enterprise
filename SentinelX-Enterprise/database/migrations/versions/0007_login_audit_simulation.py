from alembic import op

from database.schema import LOGIN_AUDIT_SIMULATION_TABLES, apply_revision

revision = '0007_login_audit_simulation'
down_revision = '0006_login_audit_ip'
branch_labels = None
depends_on = None


def upgrade():
    apply_revision(op.get_bind(), 7, LOGIN_AUDIT_SIMULATION_TABLES)


def downgrade():
    raise RuntimeError('Restore a database snapshot to roll back this migration')
