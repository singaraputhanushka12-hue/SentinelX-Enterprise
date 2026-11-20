from alembic import op

from database.schema import LOGIN_AUDIT_TABLES, apply_revision

revision = '0006_login_audit_ip'
down_revision = '0005_ai_sessions'
branch_labels = None
depends_on = None


def upgrade():
    apply_revision(op.get_bind(), 6, LOGIN_AUDIT_TABLES)


def downgrade():
    raise RuntimeError('Restore a database snapshot to roll back this migration')
