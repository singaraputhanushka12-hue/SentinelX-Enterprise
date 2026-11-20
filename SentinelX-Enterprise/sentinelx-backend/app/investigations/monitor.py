import json

from database.schema import digest, identifier, now, one, rows, run
from .report import ProviderError, evidence_packet, external_facts, generate

POLL_INTERVAL = 15
RETRY_INTERVAL = 300
LEASE_TIME = 120
SESSION_FILTER = 'org_id=:org AND incident_id=:id'


def set_monitoring(conn, org, key, active):
    stamp = now()
    if active:
        return run(conn, """INSERT INTO ai_investigation_sessions
            (org_id,incident_id,state,started,updated,next_check)
            VALUES (:org,:id,'starting',:stamp,:stamp,:stamp)
            ON CONFLICT(org_id,incident_id) DO UPDATE SET
                state='starting', updated=:stamp, next_check=:stamp, lease=NULL, error=NULL
            WHERE ai_investigation_sessions.state='stopped'""", org=org, id=key, stamp=stamp).rowcount
    return run(conn, """UPDATE ai_investigation_sessions SET state='stopped',
        updated=:stamp, lease=NULL, error=NULL WHERE """ + SESSION_FILTER + " AND state!='stopped'",
        org=org, id=key, stamp=stamp).rowcount


def save_revision(conn, org, key, report, evidence, mode):
    values = dict(org=org, id=key, revision=identifier(), report=json.dumps(report),
                  evidence=json.dumps(evidence), mode=mode, created=report['generated'])
    # Preserve a previously saved report when the first tracked revision is written.
    run(conn, """INSERT INTO ai_investigation_revisions
        SELECT org_id,incident_id,'legacy',report,evidence,mode,created
        FROM ai_investigation_reports WHERE org_id=:org AND incident_id=:id
        AND NOT EXISTS (SELECT 1 FROM ai_investigation_revisions WHERE org_id=:org AND incident_id=:id)
        ON CONFLICT(org_id,incident_id,id) DO NOTHING""", **values)
    run(conn, """INSERT INTO ai_investigation_revisions VALUES
        (:org,:id,:revision,:report,:evidence,:mode,:created)""", **values)
    run(conn, """INSERT INTO ai_investigation_reports VALUES (:org,:id,:report,:evidence,:mode,:created)
        ON CONFLICT(incident_id) DO UPDATE SET report=excluded.report,evidence=excluded.evidence,
        mode=excluded.mode,created=excluded.created WHERE ai_investigation_reports.org_id=excluded.org_id
        AND (excluded.mode='full' OR ai_investigation_reports.mode='quick')""", **values)
    return values['revision']


def process_next(engine, load_case, audit):
    stamp = now()
    with engine.begin() as conn:
        job = one(conn, """SELECT s.* FROM ai_investigation_sessions s
            JOIN incidents i ON i.org_id=s.org_id AND i.id=s.incident_id
            WHERE s.state!='stopped' AND s.next_check<=:stamp AND i.status!='closed'
            ORDER BY s.next_check,s.incident_id LIMIT 1""", stamp=stamp)
        if not job:
            return False
        org, key = job['org_id'], job['incident_id']
        packet = evidence_packet(conn, org, load_case(key, {'org_id': org}, conn), job['started'])
        fingerprint = digest(json.dumps(external_facts(packet), sort_keys=True))
        if fingerprint == job['fingerprint']:
            run(conn, """UPDATE ai_investigation_sessions SET state='monitoring', next_check=:due,
                lease=NULL,error=NULL WHERE """ + SESSION_FILTER + " AND state!='stopped' AND next_check<=:stamp",
                org=org, id=key, stamp=stamp, due=stamp+POLL_INTERVAL)
            return True
        lease = identifier()
        scope = dict(org=org, id=key, lease=lease)
        claimed = run(conn, """UPDATE ai_investigation_sessions SET state='analyzing',
            lease=:lease,next_check=:expires,updated=:stamp WHERE """ + SESSION_FILTER +
            " AND state!='stopped' AND next_check<=:stamp",
            **scope, stamp=stamp, expires=stamp+LEASE_TIME)
        if not claimed.rowcount:
            return False
    report, error = None, None
    try:
        report = generate(org, packet, 'full')
    except ProviderError as exc:
        error = str(exc)
    state = 'failed' if error else 'updated'
    with engine.begin() as conn:
        committed = run(conn, """UPDATE ai_investigation_sessions SET state=:state, error=:error,
            fingerprint=:fingerprint, updated=:stamp, next_check=:due, lease=NULL WHERE """ +
            SESSION_FILTER + " AND lease=:lease",
            **scope, state=state, error=error, fingerprint=job['fingerprint'] if error else fingerprint,
            stamp=now(), due=now()+(RETRY_INTERVAL if error else POLL_INTERVAL))
        if committed.rowcount and report:
            save_revision(conn, org, key, report, packet, 'full')
            audit(conn, org, 'investigation-worker', 'investigation.ai_report_generated', key)
        if committed.rowcount and error and error != job['error']:
            audit(conn, org, 'investigation-worker', 'investigation.ai_report_failed', key)
    return True
