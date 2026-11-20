import hashlib
import os
import secrets
import time
from pathlib import Path

from sqlalchemy import create_engine, event, text

ROOT = Path(__file__).resolve().parents[1]
TABLES = [
    """CREATE TABLE organizations (id VARCHAR(64) PRIMARY KEY, name TEXT NOT NULL, onboarded INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE users (id VARCHAR(64) PRIMARY KEY, email VARCHAR(254) UNIQUE NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL)""",
    """CREATE TABLE memberships (user_id VARCHAR(64) REFERENCES users(id), org_id VARCHAR(64) REFERENCES organizations(id), role VARCHAR(24) NOT NULL CHECK(role IN ('admin','analyst','viewer')), PRIMARY KEY(user_id,org_id))""",
    """CREATE TABLE sessions (token VARCHAR(64) PRIMARY KEY, user_id VARCHAR(64) REFERENCES users(id), org_id VARCHAR(64) REFERENCES organizations(id), expires BIGINT NOT NULL)""",
    """CREATE TABLE integrations (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) REFERENCES organizations(id), name TEXT NOT NULL, kind TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, last_event BIGINT, verified INTEGER NOT NULL DEFAULT 0, UNIQUE(org_id,id))""",
    """CREATE TABLE connector_credentials (integration_id VARCHAR(64) PRIMARY KEY REFERENCES integrations(id) ON DELETE CASCADE, token VARCHAR(64) NOT NULL)""",
    """CREATE TABLE security_events (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) NOT NULL, integration_id VARCHAR(64) NOT NULL, external_id VARCHAR(80) NOT NULL, kind VARCHAR(40) NOT NULL, asset VARCHAR(120) NOT NULL, simulated INTEGER NOT NULL, occurred BIGINT NOT NULL, received BIGINT NOT NULL, UNIQUE(integration_id,external_id), FOREIGN KEY(org_id,integration_id) REFERENCES integrations(org_id,id))""",
    """CREATE TABLE alerts (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) NOT NULL, integration_id VARCHAR(64) NOT NULL, rule VARCHAR(40) NOT NULL, severity VARCHAR(16) NOT NULL, confidence INTEGER NOT NULL, asset VARCHAR(120) NOT NULL, simulated INTEGER NOT NULL, bucket BIGINT NOT NULL, created BIGINT NOT NULL, evidence TEXT NOT NULL, UNIQUE(org_id,id), UNIQUE(integration_id,rule,asset,simulated,bucket), FOREIGN KEY(org_id,integration_id) REFERENCES integrations(org_id,id))""",
    """CREATE TABLE incidents (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) NOT NULL, alert_id VARCHAR(64) NOT NULL, title TEXT NOT NULL, status VARCHAR(24) NOT NULL, created BIGINT NOT NULL, resolution TEXT, UNIQUE(org_id,id), UNIQUE(org_id,alert_id), FOREIGN KEY(org_id,alert_id) REFERENCES alerts(org_id,id))""",
    """CREATE TABLE investigation_notes (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) NOT NULL, incident_id VARCHAR(64) NOT NULL, author TEXT NOT NULL, body TEXT NOT NULL, created BIGINT NOT NULL, FOREIGN KEY(org_id,incident_id) REFERENCES incidents(org_id,id))""",
    """CREATE TABLE response_actions (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) NOT NULL, incident_id VARCHAR(64) NOT NULL, integration_id VARCHAR(64) NOT NULL, action VARCHAR(40) NOT NULL, state VARCHAR(24) NOT NULL, requested_by VARCHAR(64) NOT NULL, approved_by VARCHAR(64), created BIGINT NOT NULL, result TEXT, UNIQUE(incident_id,action), FOREIGN KEY(org_id,incident_id) REFERENCES incidents(org_id,id), FOREIGN KEY(org_id,integration_id) REFERENCES integrations(org_id,id))""",
    """CREATE TABLE audit_logs (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) REFERENCES organizations(id), actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, created BIGINT NOT NULL)""",
    "CREATE INDEX events_tenant_time ON security_events(org_id, received)",
    "CREATE INDEX events_detection ON security_events(integration_id, kind, asset, occurred)",
    "CREATE INDEX audit_tenant_time ON audit_logs(org_id, created)",
]
ACCOUNT_TABLES = [
    """CREATE TABLE invitations (token VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) NOT NULL REFERENCES organizations(id),
        email VARCHAR(254) NOT NULL, role VARCHAR(24) NOT NULL CHECK(role IN ('analyst','viewer')), expires BIGINT NOT NULL)""",
    """CREATE TABLE recovery_codes (user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id), token VARCHAR(64) UNIQUE NOT NULL)""",
    "ALTER TABLE incidents ADD COLUMN assigned_to VARCHAR(64) REFERENCES users(id)",
]
INTELLIGENCE_TABLES = [
    """CREATE TABLE threat_indicators (id VARCHAR(64) PRIMARY KEY, org_id VARCHAR(64) NOT NULL REFERENCES organizations(id),
        indicator TEXT NOT NULL, source VARCHAR(24) NOT NULL, reputation TEXT NOT NULL, confidence INTEGER, checked BIGINT NOT NULL)""",
    """CREATE TABLE investigations (org_id VARCHAR(64) NOT NULL, incident_id VARCHAR(64) PRIMARY KEY,
        summary TEXT NOT NULL, evidence TEXT NOT NULL, created BIGINT NOT NULL,
        FOREIGN KEY(org_id,incident_id) REFERENCES incidents(org_id,id))""",
]
AI_REPORT_TABLES = [
    """CREATE TABLE ai_investigation_reports (org_id VARCHAR(64) NOT NULL, incident_id VARCHAR(64) PRIMARY KEY,
        report TEXT NOT NULL, evidence TEXT NOT NULL, mode VARCHAR(8) NOT NULL, created BIGINT NOT NULL,
        FOREIGN KEY(org_id,incident_id) REFERENCES incidents(org_id,id))""",
]

def engine_for(variable, file):
    url = os.getenv(variable, 'sqlite:///' + (ROOT / 'database' / file).as_posix())
    engine = create_engine(url, pool_pre_ping=True)
    if engine.dialect.name == 'sqlite':
        @event.listens_for(engine, 'connect')
        def enforce_foreign_keys(connection, _record):
            connection.execute('PRAGMA foreign_keys=ON')
    return engine

def run(conn, statement, **params):
    return conn.execute(text(statement), params)

def rows(conn, statement, **params):
    return [dict(row) for row in run(conn, statement, **params).mappings()]

def one(conn, statement, **params):
    row = run(conn, statement, **params).mappings().first()
    return dict(row) if row else None

def now():
    return int(time.time())

def identifier():
    return secrets.token_hex(16)

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    value = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=1, maxmem=64*1024*1024)
    return salt + ':' + value.hex()

def password_matches(password, stored):
    return secrets.compare_digest(password_hash(password, stored.split(':')[0]), stored)

def apply_revision(conn, version, statements):
    run(conn, 'CREATE TABLE IF NOT EXISTS local_schema (version INTEGER PRIMARY KEY)')
    if not one(conn, 'SELECT version FROM local_schema WHERE version=:version', version=version):
        for statement in statements:
            run(conn, statement)
        run(conn, 'INSERT INTO local_schema VALUES (:version)', version=version)

def initialize(engine, *revisions):
    with engine.begin() as conn:
        for version, statements in enumerate(revisions, start=1):
            apply_revision(conn, version, statements)



AI_SESSION_TABLES = [
    """CREATE TABLE ai_investigation_sessions (
        org_id VARCHAR(64) NOT NULL, incident_id VARCHAR(64) NOT NULL,
        state VARCHAR(16) NOT NULL, started BIGINT NOT NULL, updated BIGINT NOT NULL,
        next_check BIGINT NOT NULL, fingerprint VARCHAR(64), lease VARCHAR(64), error TEXT,
        PRIMARY KEY(org_id,incident_id),
        FOREIGN KEY(org_id,incident_id) REFERENCES incidents(org_id,id))""",
    """CREATE TABLE ai_investigation_revisions (
        org_id VARCHAR(64) NOT NULL, incident_id VARCHAR(64) NOT NULL,
        id VARCHAR(64) NOT NULL, report TEXT NOT NULL, evidence TEXT NOT NULL,
        mode VARCHAR(8) NOT NULL, created BIGINT NOT NULL,
        PRIMARY KEY(org_id,incident_id,id),
        FOREIGN KEY(org_id,incident_id) REFERENCES incidents(org_id,id))""",
    "CREATE INDEX ai_sessions_due ON ai_investigation_sessions(state,next_check)",
    "CREATE INDEX ai_revisions_created ON ai_investigation_revisions(org_id,incident_id,created)",
    "CREATE INDEX ai_event_scope ON security_events(integration_id,asset,simulated,occurred)",
    "CREATE INDEX ai_alert_scope ON alerts(integration_id,asset,simulated,created)",
]

LOGIN_AUDIT_TABLES = [
    'ALTER TABLE audit_logs ADD COLUMN source_ip VARCHAR(45)',
]

LOGIN_AUDIT_SIMULATION_TABLES = [
    'ALTER TABLE audit_logs ADD COLUMN source_ip_simulated INTEGER NOT NULL DEFAULT 0',
]
