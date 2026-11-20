import asyncio
import json
import logging
import os
import re
import secrets
from contextlib import asynccontextmanager
from ipaddress import ip_address
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, validator
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool

from database.schema import ACCOUNT_TABLES, AI_REPORT_TABLES, AI_SESSION_TABLES, INTELLIGENCE_TABLES, LOGIN_AUDIT_SIMULATION_TABLES, LOGIN_AUDIT_TABLES, TABLES, digest, engine_for, identifier, initialize, now, one, password_hash, password_matches, rows, run
from service_common import ApiBoundary
from .investigations.monitor import process_next, save_revision, set_monitoring
from .investigations.provider import suggest
from .investigations.report import ProviderError, SECTIONS, evidence_packet, generate, provider_state

engine = engine_for('SENTINELX_DATABASE_URL', 'sentinelx.sqlite3')
COOKIE = 'sentinelx_session'
DAY = 86400
KINDS = ('Website / Web Application', 'Windows Endpoint', 'Wazuh', 'Suricata', 'Linux Server', 'Cloud Monitoring', 'Custom Webhook', 'DemoLab', 'Login Portal')
PORTAL_RULE = 'portal_auth_failure'
PORTAL_REASON = 'Three incorrect password attempts were recorded for the same account within two minutes.'
PORTAL_THREAT = 'Password guessing, brute-force attempts, or unauthorized account access.'
PORTAL_ACTIONS = [
    'Review the authentication logs.',
    'Verify whether the account owner recognizes the attempts.',
    'Apply rate limiting or temporary account protection.',
    'Enable MFA where appropriate.',
    'Investigate additional suspicious indicators.',
    'Escalate the incident if necessary.',
]
RULES = {
    PORTAL_RULE: (3, 'high', 85, 'Repeated Failed Login Attempts'),
    'auth_failure': (5, 'high', 85, 'Repeated authentication failures'),
    'auth_anomaly': (1, 'medium', 65, 'Authentication anomaly'),
    'request_burst': (3, 'medium', 65, 'Unusual request volume'),
    'api_denied': (3, 'medium', 75, 'Repeated API access denials'),
    'web_signal': (1, 'medium', 65, 'Suspicious request signal'),
    'indicator_match': (1, 'high', 80, 'Reported indicator match'),
    'endpoint_anomaly': (1, 'medium', 65, 'Endpoint behavior anomaly'),
    'app_error': (3, 'medium', 80, 'Application error spike'),
    'service_unavailable': (1, 'high', 80, 'Service unavailable'),
}

async def monitor_investigations():
    while True:
        try:
            if await run_in_threadpool(process_next, engine, investigation, audit):
                await asyncio.sleep(0)
                continue
        except Exception:
            logging.getLogger(__name__).exception('Investigation monitoring cycle failed')
        await asyncio.sleep(3)


@asynccontextmanager
async def lifespan(_app):
    initialize(engine, TABLES, ACCOUNT_TABLES, INTELLIGENCE_TABLES, AI_REPORT_TABLES, AI_SESSION_TABLES, LOGIN_AUDIT_TABLES, LOGIN_AUDIT_SIMULATION_TABLES)
    worker = asyncio.create_task(monitor_investigations())
    try:
        yield
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)

app = FastAPI(title='SentinelX Enterprise', version='0.1.0', lifespan=lifespan)

app.add_middleware(ApiBoundary, prefix='/api/', origin_setting='SENTINELX_ORIGINS',
                   default_origins='http://127.0.0.1:5174,http://localhost:5174', max_body=16384)

def db():
    with engine.begin() as conn:
        yield conn

def required(value):
    if value is None:
        raise HTTPException(404, 'Record unavailable')
    return value

def audit(conn, org, actor, action, target, *, source_ip=None, source_ip_simulated=False, occurred=None, event_id=None):
    run(conn, '''INSERT INTO audit_logs (id,org_id,actor,action,target,created,source_ip,source_ip_simulated)
        VALUES (:id,:org,:actor,:action,:target,:created,:ip,:simulated_ip)''',
        id=event_id or identifier(), org=org, actor=actor, action=action, target=target,
        created=now() if occurred is None else occurred, ip=source_ip, simulated_ip=int(source_ip_simulated))

def session(conn, request):
    return one(conn, '''SELECT u.id, u.name, u.email, o.id AS org_id, o.name AS organization, o.onboarded, m.role
        FROM sessions s JOIN memberships m ON m.user_id=s.user_id AND m.org_id=s.org_id
        JOIN users u ON u.id=m.user_id JOIN organizations o ON o.id=m.org_id
        WHERE s.token=:token AND s.expires>:time''', token=digest(request.cookies.get(COOKIE, '')), time=now())

def member(request: Request, conn=Depends(db, scope='function')):
    user = session(conn, request)
    if not user:
        raise HTTPException(401, 'Sign in to continue')
    return user

def analyst(user=Depends(member)):
    if user['role'] not in ('admin', 'analyst'):
        raise HTTPException(403, 'Analyst access required')
    return user

def admin(user=Depends(member)):
    if user['role'] != 'admin':
        raise HTTPException(403, 'Administrator access required')
    return user

def establish(conn, response, user, org):
    token = secrets.token_urlsafe(32)
    run(conn, 'INSERT INTO sessions VALUES (:token,:user,:org,:expires)', token=digest(token), user=user, org=org, expires=now()+DAY)
    response.set_cookie(COOKIE, token, max_age=DAY, httponly=True, samesite='strict',
                        secure=os.getenv('SENTINELX_SECURE_COOKIES') == '1')

class Login(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)

class Registration(Login):
    organization: str = Field(min_length=2, max_length=100)
    name: str = Field(min_length=2, max_length=100)
    confirm: str = Field(max_length=128)

@app.post('/api/register', status_code=201)
def register(body: Registration, response: Response, conn=Depends(db, scope='function')):
    org, user = identifier(), identifier()
    email = body.email.strip().casefold()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or len(body.password) < 12 or body.password != body.confirm:
        raise HTTPException(422, 'Supply a valid email and matching passwords of at least 12 characters')
    if min(len(body.organization.strip()), len(body.name.strip())) < 2:
        raise HTTPException(422, 'Provide an organization and administrator name')
    try:
        run(conn, 'INSERT INTO organizations (id,name) VALUES (:id,:name)', id=org, name=body.organization.strip())
        run(conn, 'INSERT INTO users VALUES (:id,:email,:name,:password)', id=user, email=email, name=body.name.strip(), password=password_hash(body.password))
        run(conn, "INSERT INTO memberships VALUES (:user,:org,'admin')", user=user, org=org)
    except IntegrityError:
        raise HTTPException(409, 'This email is already registered')
    establish(conn, response, user, org)
    audit(conn, org, user, 'organization.registered', org)
    return {'onboarded': False}

@app.post('/api/login')
def login(body: Login, response: Response, conn=Depends(db, scope='function')):
    user = one(conn, '''SELECT u.*,m.org_id,o.onboarded FROM users u JOIN memberships m ON m.user_id=u.id
        JOIN organizations o ON o.id=m.org_id WHERE u.email=:email ORDER BY m.org_id LIMIT 1''', email=body.email.strip().casefold())
    fallback = '0'*32 + ':' + '0'*128
    matches = password_matches(body.password, user['password'] if user else fallback)
    if not user or not matches:
        raise HTTPException(401, 'Invalid email or password')
    establish(conn, response, user['id'], user['org_id'])
    return {'onboarded': bool(user['onboarded'])}

@app.post('/api/logout')
def logout(request: Request, response: Response, conn=Depends(db, scope='function')):
    run(conn, 'DELETE FROM sessions WHERE token=:token', token=digest(request.cookies.get(COOKIE, '')))
    response.delete_cookie(COOKIE)
    return {'ok': True}

@app.get('/api/me')
def me(user=Depends(member)):
    return user

class Invitation(BaseModel):
    email: str = Field(min_length=3,max_length=254,regex=r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
    role: str = Field(regex=r'^(analyst|viewer)$')

class Acceptance(Login):
    name: str = Field(min_length=2,max_length=100)
    token: str = Field(min_length=43,max_length=43)

class Reset(BaseModel):
    token: str = Field(min_length=43,max_length=43)
    password: str = Field(min_length=12,max_length=128)

@app.get('/api/team')
def team(user=Depends(member), conn=Depends(db, scope='function')):
    return rows(conn, '''SELECT u.id,u.name,m.role FROM memberships m JOIN users u ON u.id=m.user_id
        WHERE m.org_id=:org ORDER BY u.name''', org=user['org_id'])

@app.post('/api/invitations',status_code=201)
def invite(body: Invitation, user=Depends(admin), conn=Depends(db, scope='function')):
    token=secrets.token_urlsafe(32)
    org=user['org_id']
    run(conn,'INSERT INTO invitations VALUES (:token,:org,:email,:role,:expires)',
        token=digest(token),org=org,email=body.email.casefold(),role=body.role,expires=now()+DAY)
    audit(conn,org,user['id'],'invitation.created',body.email.casefold())
    return {'token':token}

@app.post('/api/accept-invitation',status_code=201)
def accept(body: Acceptance, response: Response, conn=Depends(db, scope='function')):
    email=body.email.strip().casefold()
    token=digest(body.token)
    if len(body.password)<12 or len(body.name.strip())<2:
        raise HTTPException(422,'Enter a name and a password of at least 12 characters')
    invitation=one(conn,'''DELETE FROM invitations WHERE token=:token AND email=:email AND expires>:time
        RETURNING org_id,role''',token=token,email=email,time=now())
    if not invitation:
        raise HTTPException(422,'Invalid or expired invitation')
    org=invitation['org_id']
    user=identifier()
    try:
        run(conn,'INSERT INTO users VALUES (:id,:email,:name,:password)',
            id=user,email=email,name=body.name.strip(),password=password_hash(body.password))
        run(conn,'INSERT INTO memberships VALUES (:user,:org,:role)',user=user,org=org,role=invitation['role'])
    except IntegrityError:
        raise HTTPException(409,'This email is already registered')
    establish(conn,response,user,org)
    audit(conn,org,user,'invitation.accepted',user)
    return {'onboarded':bool(one(conn,'SELECT onboarded FROM organizations WHERE id=:id',id=org)['onboarded'])}

@app.post('/api/recovery-code')
def recovery_code(user=Depends(member), conn=Depends(db, scope='function')):
    token=secrets.token_urlsafe(32)
    run(conn,'''INSERT INTO recovery_codes VALUES (:id,:token)
        ON CONFLICT(user_id) DO UPDATE SET token=excluded.token''',id=user['id'],token=digest(token))
    audit(conn,user['org_id'],user['id'],'account.recovery_code_created',user['id'])
    return {'token':token}

@app.post('/api/reset-password')
def reset_password(body: Reset, conn=Depends(db, scope='function')):
    record=one(conn,'DELETE FROM recovery_codes WHERE token=:token RETURNING user_id',token=digest(body.token))
    if not record:
        raise HTTPException(422,'Invalid or used recovery code')
    user=record['user_id']
    run(conn,'UPDATE users SET password=:password WHERE id=:id',password=password_hash(body.password),id=user)
    run(conn,'DELETE FROM sessions WHERE user_id=:id',id=user)
    for membership in rows(conn,'SELECT org_id FROM memberships WHERE user_id=:id',id=user):
        audit(conn,membership['org_id'],user,'account.password_reset',user)
    return {'ok':True}

class IntegrationInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    kind: str = Field(max_length=40)

def integration(conn, org, key):
    return required(one(conn, 'SELECT * FROM integrations WHERE org_id=:org AND id=:id', org=org, id=key))

def issue(conn, key):
    token = secrets.token_urlsafe(32)
    run(conn, 'DELETE FROM connector_credentials WHERE integration_id=:id', id=key)
    run(conn, 'INSERT INTO connector_credentials VALUES (:id,:token)', id=key, token=digest(token))
    return token

@app.get('/api/integrations')
def integrations(user=Depends(member), conn=Depends(db, scope='function')):
    return rows(conn, 'SELECT * FROM integrations WHERE org_id=:org AND active>=0 ORDER BY name', org=user['org_id'])

@app.get('/api/integrations/{key}/activity')
def integration_activity(key: str, user=Depends(member), conn=Depends(db, scope='function')):
    org=user['org_id']
    integration(conn,org,key)
    return rows(conn,'''SELECT * FROM security_events WHERE org_id=:org AND integration_id=:id
        ORDER BY received DESC,id LIMIT 30''',org=org,id=key)

@app.post('/api/integrations', status_code=201)
def create_integration(body: IntegrationInput, user=Depends(admin), conn=Depends(db, scope='function')):
    if body.kind not in KINDS or len(body.name.strip()) < 2:
        raise HTTPException(422, 'Select an integration type and enter its name')
    key = identifier()
    run(conn, 'INSERT INTO integrations (id,org_id,name,kind) VALUES (:id,:org,:name,:kind)', id=key, org=user['org_id'], **body.dict())
    token = issue(conn, key)
    audit(conn, user['org_id'], user['id'], 'integration.created', key)
    return {'id': key, 'token': token}

@app.post('/api/integrations/{key}/{operation}')
def change_integration(key: str, operation: str, user=Depends(admin), conn=Depends(db, scope='function')):
    item = integration(conn, user['org_id'], key)
    if item['active']<0:
        raise HTTPException(404,'Record unavailable')
    output = {'id': key}
    if operation == 'verify':
        if not item['active'] or not item['last_event'] or item['last_event'] < now()-300:
            raise HTTPException(409, 'Send an authenticated event within five minutes and try again')
        run(conn, 'UPDATE integrations SET verified=1 WHERE id=:id', id=key)
        run(conn, 'UPDATE organizations SET onboarded=1 WHERE id=:org', org=user['org_id'])
    elif operation in ('rotate', 'disable', 'reconnect', 'remove'):
        active = -1 if operation=='remove' else int(operation in ('rotate', 'reconnect'))
        run(conn, 'UPDATE integrations SET active=:active, verified=0,last_event=NULL WHERE id=:id', active=active, id=key)
        if active==1:
            output['token'] = issue(conn, key)
        elif operation == 'remove':
            run(conn, 'DELETE FROM connector_credentials WHERE integration_id=:id', id=key)
    else:
        raise HTTPException(404, 'Unknown integration operation')
    audit(conn, user['org_id'], user['id'], 'integration.'+operation, key)
    return output

def connector(key: str, authorization: str = Header(default=''), conn=Depends(db, scope='function')):
    item = one(conn, '''SELECT i.*, c.token FROM integrations i JOIN connector_credentials c ON c.integration_id=i.id
        WHERE i.id=:id AND i.active=1''', id=key)
    prefix, _, token = authorization.partition(' ')
    if not item or prefix.lower() != 'bearer' or not secrets.compare_digest(item['token'], digest(token)):
        raise HTTPException(401, 'Invalid connector credentials')
    return item

class EventInput(BaseModel):
    external_id: str = Field(min_length=8, max_length=80)
    kind: str = Field(min_length=2, max_length=40, regex=r'^[a-z_]+$')
    asset: str = Field(min_length=1, max_length=120)
    occurred: int
    simulated: bool = False
    source_ip: str | None = None
    source_ip_simulated: bool = False

    @validator('source_ip', pre=True)
    def validate_source_ip(cls, value):
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > 45 or '%' in value:
            raise ValueError('Source IP must be an IPv4 or IPv6 address')
        return str(ip_address(value))

def detect(conn, item, body):
    if body.kind == PORTAL_RULE:
        return None
    rule_key = PORTAL_RULE if item['kind'] == 'Login Portal' and body.kind == 'auth_failure' else body.kind
    rule = RULES.get(rule_key)
    if not rule:
        return None
    threshold, severity, confidence, _label = rule
    stamp = now()
    stop = max(stamp, body.occurred) if rule_key == PORTAL_RULE else stamp+30
    start = stop-120 if rule_key == PORTAL_RULE else stamp-120
    evidence = rows(conn, '''SELECT id FROM security_events WHERE integration_id=:integration AND kind=:kind
        AND asset=:asset AND simulated=:simulated AND occurred>=:start AND occurred<=:stop ORDER BY occurred,id''',
        integration=item['id'], kind=body.kind, asset=body.asset, simulated=int(body.simulated),
        start=start, stop=stop)
    if len(evidence) < threshold:
        return None
    recent=one(conn, '''SELECT id FROM alerts WHERE integration_id=:integration AND rule=:rule
        AND asset=:asset AND simulated=:simulated AND created>=:since''', integration=item['id'],rule=rule_key,
        asset=body.asset,simulated=int(body.simulated),since=stamp-120)
    if recent:
        return None
    alert = identifier()
    inserted = run(conn, '''INSERT INTO alerts VALUES (:id,:org,:integration,:rule,:severity,:confidence,:asset,
        :simulated,:bucket,:created,:evidence) ON CONFLICT(integration_id,rule,asset,simulated,bucket) DO NOTHING''',
        id=alert, org=item['org_id'], integration=item['id'], rule=rule_key, severity=severity, confidence=confidence,
        asset=body.asset, simulated=int(body.simulated), bucket=stamp//120, created=stamp, evidence=json.dumps([event['id'] for event in evidence]))
    if inserted.rowcount:
        audit(conn, item['org_id'], item['id'], 'alert.detected', alert)
        if rule_key == PORTAL_RULE:
            open_incident(conn, item['org_id'], item['id'], alert, rule_key)
        return alert
    return None

@app.post('/api/connectors/{key}/events', status_code=202)
def ingest(body: EventInput, item=Depends(connector), conn=Depends(db, scope='function')):
    portal_auth = item['kind'] == 'Login Portal' and body.kind in ('auth_success', 'auth_failure')
    if body.source_ip_simulated and not (portal_auth and body.simulated and body.source_ip == '192.0.2.10'):
        raise HTTPException(422, 'Simulated IP is only accepted on simulated Login Portal authentication events')
    timestamp = now()
    if not timestamp-120 <= body.occurred <= timestamp+30:
        raise HTTPException(422, 'Event timestamp outside the acceptance window')
    # Serialize ingestion per connector before checking its rate budget.
    locked = run(conn, 'UPDATE integrations SET last_event=last_event WHERE id=:id AND active=1 AND EXISTS (SELECT 1 FROM connector_credentials WHERE integration_id=:id AND token=:token)', id=item['id'], token=item['token'])
    if not locked.rowcount:
        raise HTTPException(401, 'Connector credentials changed')
    if one(conn, 'SELECT id FROM security_events WHERE integration_id=:id AND external_id=:external', id=item['id'], external=body.external_id):
        raise HTTPException(409, 'Duplicate event')
    count = one(conn, 'SELECT COUNT(*) AS total FROM security_events WHERE integration_id=:id AND received>=:start', id=item['id'], start=timestamp-60)
    if count['total'] >= 120:
        raise HTTPException(429, 'Connector rate limit reached', headers={'Retry-After':'60'})
    key = identifier()
    run(conn, '''INSERT INTO security_events VALUES (:id,:org,:integration,:external,:kind,:asset,:simulated,:occurred,:received)''',
        id=key, org=item['org_id'], integration=item['id'], external=body.external_id, kind=body.kind,
        asset=body.asset, simulated=int(body.simulated), occurred=body.occurred, received=timestamp)
    run(conn, 'UPDATE integrations SET last_event=:received WHERE id=:id', received=timestamp, id=item['id'])
    if portal_auth:
        audit(conn, item['org_id'], body.asset, body.kind, item['name'],
              source_ip=body.source_ip, source_ip_simulated=body.source_ip_simulated,
              occurred=body.occurred, event_id=key)
    result = {'id': key, 'alert_id': detect(conn, item, body)}
    if body.kind == 'connector_check':
        result['integration_kind'] = item['kind']
    return result

@app.get('/api/events')
def events(kind: str = '', user=Depends(member), conn=Depends(db, scope='function')):
    return rows(conn, '''SELECT * FROM security_events WHERE org_id=:org AND (:kind='' OR kind=:kind)
        ORDER BY received DESC,id LIMIT 100''', org=user['org_id'], kind=kind)

@app.get('/api/events/{key}')
def event_detail(key: str, user=Depends(member), conn=Depends(db, scope='function')):
    return required(one(conn, 'SELECT * FROM security_events WHERE org_id=:org AND id=:id', org=user['org_id'], id=key))

def snapshot(request):
    with engine.begin() as conn:
        user = session(conn, request)
        if user:
            return rows(conn, 'SELECT * FROM security_events WHERE org_id=:org ORDER BY received DESC,id LIMIT 30', org=user['org_id'])
    return None

@app.get('/api/live')
async def live(request: Request):
    if await run_in_threadpool(snapshot, request) is None:
        raise HTTPException(401, 'Sign in to continue')
    async def stream():
        previous = None
        while True:
            latest = await run_in_threadpool(snapshot, request)
            if latest is None:
                return
            payload = json.dumps(latest)
            yield 'data: '+payload+'\n\n' if payload != previous else ': heartbeat\n\n'
            previous = payload
            await asyncio.sleep(2)
    return StreamingResponse(stream(), media_type='text/event-stream', headers={'X-Accel-Buffering':'no'})

@app.get('/api/overview')
def overview(user=Depends(member), conn=Depends(db, scope='function')):
    org = user['org_id']
    totals = one(conn, '''SELECT
        (SELECT COUNT(*) FROM security_events WHERE org_id=:org) AS events,
        (SELECT COUNT(DISTINCT asset) FROM security_events WHERE org_id=:org) AS assets,
        (SELECT COUNT(*) FROM alerts a WHERE a.org_id=:org AND NOT EXISTS
          (SELECT 1 FROM incidents i WHERE i.org_id=a.org_id AND i.alert_id=a.id AND i.status IN ('resolved','closed'))) AS alerts,
        (SELECT COUNT(*) FROM alerts WHERE org_id=:org AND severity='critical') AS critical,
        (SELECT COUNT(*) FROM incidents WHERE org_id=:org AND status NOT IN ('closed','resolved')) AS incidents,
        (SELECT COUNT(*) FROM incidents WHERE org_id=:org AND status IN ('closed','resolved')) AS resolved,
        (SELECT COUNT(*) FROM integrations WHERE org_id=:org AND verified=1 AND active=1) AS integrations''', org=org)
    series = rows(conn, '''SELECT CAST(received / 3600 AS BIGINT) AS bucket, SUM(CASE WHEN simulated=1 THEN 1 ELSE 0 END) AS simulated,
        SUM(CASE WHEN simulated=0 THEN 1 ELSE 0 END) AS observed FROM security_events WHERE org_id=:org AND received>=:since
        GROUP BY CAST(received / 3600 AS BIGINT) ORDER BY bucket''', org=org, since=now()-86400)
    severity = rows(conn, 'SELECT severity,COUNT(*) AS total FROM alerts WHERE org_id=:org GROUP BY severity', org=org)
    response_time = one(conn, '''SELECT AVG(l.created-r.created) AS seconds FROM response_actions r JOIN audit_logs l
        ON l.org_id=r.org_id AND l.target=r.id AND l.action IN ('response.restricted','response.restored') WHERE r.org_id=:org''', org=org)
    categories = rows(conn,'SELECT rule AS name,COUNT(*) AS total FROM alerts WHERE org_id=:org GROUP BY rule',org=org)
    states = rows(conn,'SELECT status AS name,COUNT(*) AS total FROM incidents WHERE org_id=:org GROUP BY status',org=org)
    health = rows(conn,'''SELECT CASE WHEN active=0 THEN 'Disconnected' WHEN verified=0 THEN 'Configuration required'
        WHEN last_event>=:recent THEN 'Receiving events' ELSE 'Connected' END AS name, COUNT(*) AS total
        FROM integrations WHERE org_id=:org AND active>=0 GROUP BY 1''',org=org,recent=now()-300)
    trends = rows(conn,'''SELECT CAST(created / 3600 AS BIGINT) AS bucket,COUNT(*) AS total
        FROM alerts WHERE org_id=:org AND created>=:since GROUP BY 1 ORDER BY 1''',org=org,since=now()-86400)
    return {'totals': totals, 'series': series, 'severity': severity, 'response_seconds': response_time['seconds'],
            'categories':categories,'incident_states':states,'integration_health':health,'alert_trends':trends}

@app.get('/api/alerts')
def alerts(user=Depends(member), conn=Depends(db, scope='function')):
    results = rows(conn, 'SELECT * FROM alerts WHERE org_id=:org ORDER BY created DESC,id LIMIT 100', org=user['org_id'])
    for result in results:
        result['label'] = RULES[result['rule']][3]
        result['evidence'] = json.loads(result['evidence'])
        if result['rule'] == PORTAL_RULE:
            result.update(reason=PORTAL_REASON, potential_threat=PORTAL_THREAT, recommended_actions=PORTAL_ACTIONS)
    return results

@app.get('/api/incidents')
def incidents(user=Depends(member), conn=Depends(db, scope='function')):
    return rows(conn, 'SELECT * FROM incidents WHERE org_id=:org ORDER BY created DESC,id LIMIT 100', org=user['org_id'])

@app.post('/api/alerts/{key}/incident', status_code=201)
def create_incident(key: str, user=Depends(analyst), conn=Depends(db, scope='function')):
    org = user['org_id']
    alert = required(one(conn, 'SELECT * FROM alerts WHERE id=:id AND org_id=:org', id=key, org=org))
    return {'id': open_incident(conn, org, user['id'], key, alert['rule'])}

def open_incident(conn, org, actor, key, rule):
    incident = identifier()
    inserted = run(conn, """INSERT INTO incidents (id,org_id,alert_id,title,status,created)
        VALUES (:id,:org,:alert,:title,'investigating',:created)
        ON CONFLICT(org_id,alert_id) DO NOTHING""", id=incident, org=org, alert=key, title=RULES[rule][3], created=now())
    if inserted.rowcount:
        audit(conn, org, actor, 'incident.opened', incident)
    else:
        incident = one(conn, 'SELECT id FROM incidents WHERE org_id=:org AND alert_id=:id', org=org, id=key)['id']
    if lock_incident(conn, org, incident)['status'] != 'closed' and set_monitoring(conn, org, incident, True):
        audit(conn, org, actor, 'investigation.monitoring_started', incident)
    return incident

def incident_record(conn, org, key):
    return required(one(conn, 'SELECT * FROM incidents WHERE org_id=:org AND id=:id', org=org, id=key))

def lock_incident(conn, org, key):
    return required(one(conn, 'UPDATE incidents SET status=status WHERE org_id=:org AND id=:id RETURNING *', org=org,id=key))

@app.get('/api/incidents/{key}')
def investigation(key: str, user=Depends(member), conn=Depends(db, scope='function')):
    org = user['org_id']
    record = incident_record(conn, org, key)
    alert = required(one(conn, 'SELECT * FROM alerts WHERE org_id=:org AND id=:id', org=org, id=record['alert_id']))
    evidence = [one(conn, 'SELECT * FROM security_events WHERE org_id=:org AND id=:id', org=org, id=event)
                for event in json.loads(alert['evidence'])]
    technique = 'T1110 · Brute Force (possible)' if alert['rule'] in ('auth_failure', PORTAL_RULE) else None
    eligible = alert['rule']=='auth_failure' and alert['simulated'] and alert['asset']=='demo-test-account'
    summary = f"{len(evidence)} {alert['rule'].replace('_', ' ')} events were correlated for {alert['asset']}."
    portal_alert = alert['rule'] == PORTAL_RULE
    if portal_alert:
        summary = PORTAL_REASON
    draft=one(conn,'SELECT summary,evidence,created FROM investigations WHERE org_id=:org AND incident_id=:id',
              org=org,id=key)
    if draft:
        draft['evidence_ids']=json.loads(draft.pop('evidence'))
    timeline=rows(conn, '''SELECT action,actor,created FROM audit_logs WHERE org_id=:org AND
        (target=:id OR target IN (SELECT id FROM response_actions WHERE org_id=:org AND incident_id=:id))
        ORDER BY created,id LIMIT 100''',org=org,id=key)
    return {
        **record, 'evidence': evidence, 'notes': rows(conn, 'SELECT author,body,created FROM investigation_notes WHERE org_id=:org AND incident_id=:id ORDER BY created', org=org,id=key),
        'method':'Evidence rules', 'summary':summary, 'technique':technique, 'confidence':alert['confidence'],
        'impact': PORTAL_THREAT if portal_alert else ('Possible account abuse requiring review' if technique else 'Operational or security impact requires review'),
        'limitations':'Available telemetry establishes the reported signals. Intent and compromise remain unverified.',
        'next_steps': ' '.join(PORTAL_ACTIONS) if portal_alert else 'Review the evidence timestamps and verify the affected asset with its owner.',
        'recommendation':'Temporarily restrict the DemoLab test account' if eligible else 'Escalate to the asset owner for investigation',
        'eligible':bool(eligible),
        'draft':draft,
        'timeline':timeline,
        'responses':rows(conn,'SELECT id,action,state,result FROM response_actions WHERE org_id=:org AND incident_id=:id',org=org,id=key),
    }

@app.post('/api/incidents/{key}/ai-summary')
def generate_draft(key: str, user=Depends(analyst), conn=Depends(db, scope='function')):
    case=investigation(key,user,conn)
    if not provider_state(user['org_id'])['ready'] or not os.getenv('SENTINELX_LLM_GATEWAY_URL'):
        return {'generated':False}
    draft=suggest(case['evidence'])
    if not draft:
        return {'generated':False}
    org=user['org_id']
    run(conn,'''INSERT INTO investigations VALUES (:org,:id,:summary,:evidence,:created)
        ON CONFLICT(incident_id) DO UPDATE SET summary=excluded.summary,evidence=excluded.evidence,created=excluded.created''',
        org=org,id=key,summary=draft['summary'],evidence=json.dumps(draft['evidence_ids']),created=now())
    audit(conn,org,user['id'],'investigation.ai_draft_saved',key)
    return {'generated':True}

@app.get('/api/incidents/{key}/ai-evidence')
def ai_evidence(key: str, user=Depends(member), conn=Depends(db, scope='function')):
    case=investigation(key,user,conn)
    org=user['org_id']
    stored=one(conn,'SELECT report,evidence FROM ai_investigation_reports WHERE org_id=:org AND incident_id=:id',org=org,id=key)
    saved={field:json.loads(value) for field,value in stored.items()} if stored else None
    monitor = one(conn, 'SELECT state,started,updated,error FROM ai_investigation_sessions WHERE org_id=:org AND incident_id=:id',
                  org=org, id=key)
    revisions = rows(conn, '''SELECT id,mode,created FROM ai_investigation_revisions
        WHERE org_id=:org AND incident_id=:id ORDER BY created DESC,id DESC LIMIT 100''', org=org, id=key)
    current_revision = one(conn, '''SELECT r.id FROM ai_investigation_revisions r
        JOIN ai_investigation_reports p ON r.org_id=p.org_id AND r.incident_id=p.incident_id
        AND r.report=p.report AND r.evidence=p.evidence
        WHERE r.org_id=:org AND r.incident_id=:id ORDER BY r.created DESC,r.id DESC LIMIT 1''', org=org, id=key)
    return {'evidence':evidence_packet(conn,org,case,monitor['started'] if monitor else None),'status':provider_state(org),
            'monitor':monitor,'revisions':revisions,'current_revision':current_revision['id'] if current_revision else None,
            'organization':user['organization'],'sections':SECTIONS,'saved':saved}

class AIReportRequest(BaseModel):
    mode: str = Field(regex=r'^(quick|full)$')

@app.post('/api/incidents/{key}/ai-report')
def ai_report(key: str, body: AIReportRequest, user=Depends(analyst), conn=Depends(db, scope='function')):
    case=investigation(key,user,conn)
    org=user['org_id']
    monitor=one(conn,'SELECT started FROM ai_investigation_sessions WHERE org_id=:org AND incident_id=:id',org=org,id=key)
    evidence=evidence_packet(conn,org,case,monitor['started'] if monitor else None)
    try:
        result=generate(org,evidence,body.mode)
    except ProviderError as error:
        return {'generated':False,'message':str(error)}
    revision = save_revision(conn, org, key, result, evidence, body.mode)
    audit(conn,org,user['id'],'investigation.ai_report_generated',key)
    return {'generated':True,'report':result,'evidence':evidence,'revision':revision}

@app.get('/api/incidents/{key}/ai-revisions/{revision}')
def ai_revision(key: str, revision: str, user=Depends(member), conn=Depends(db, scope='function')):
    stored = required(one(conn, '''SELECT report,evidence FROM ai_investigation_revisions
        WHERE org_id=:org AND incident_id=:id AND id=:revision''', org=user['org_id'], id=key, revision=revision))
    return {field: json.loads(value) for field, value in stored.items()}


class MonitoringRequest(BaseModel):
    active: bool


@app.post('/api/incidents/{key}/ai-monitor')
def ai_monitor(key: str, body: MonitoringRequest, user=Depends(analyst), conn=Depends(db, scope='function')):
    org = user['org_id']
    if lock_incident(conn, org, key)['status'] == 'closed':
        raise HTTPException(409, 'The investigation is closed')
    if set_monitoring(conn, org, key, body.active):
        action = 'investigation.monitoring_resumed' if body.active else 'investigation.monitoring_stopped'
        audit(conn, org, user['id'], action, key)
    return {'ok': True}


class Note(BaseModel):
    body: str = Field(min_length=1, max_length=4000)

class Assignment(BaseModel):
    user_id: str = Field(regex=r'^[a-f0-9]{32}$')

@app.post('/api/incidents/{key}/assign')
def assign_incident(key: str, body: Assignment, user=Depends(analyst), conn=Depends(db, scope='function')):
    org=user['org_id']
    required(one(conn, "SELECT user_id FROM memberships WHERE org_id=:org AND user_id=:id AND role IN ('admin','analyst')",
                 org=org,id=body.user_id))
    updated=run(conn,"UPDATE incidents SET assigned_to=:assignee WHERE org_id=:org AND id=:id AND status!='closed'",
                assignee=body.user_id,org=org,id=key)
    if not updated.rowcount:
        raise HTTPException(404,'Open incident unavailable')
    audit(conn,org,user['id'],'incident.assigned',key)
    return {'ok':True}

@app.post('/api/incidents/{key}/notes')
def add_note(key: str, body: Note, user=Depends(analyst), conn=Depends(db, scope='function')):
    org = user['org_id']
    incident_record(conn, org, key)
    run(conn, 'INSERT INTO investigation_notes VALUES (:id,:org,:incident,:author,:body,:created)',
        id=identifier(), org=org, incident=key, author=user['name'], body=body.body, created=now())
    audit(conn, org, user['id'], 'incident.note_added', key)
    return {'ok':True}

@app.post('/api/incidents/{key}/close')
def close_incident(key: str, body: Note, user=Depends(analyst), conn=Depends(db, scope='function')):
    org = user['org_id']
    lock_incident(conn, org, key)
    if one(conn, "SELECT id FROM response_actions WHERE org_id=:org AND incident_id=:id AND state IN ('pending','approved')", org=org, id=key):
        raise HTTPException(409, 'Finish pending response actions before closing the incident')
    completed = {item['action'] for item in rows(conn, '''SELECT action FROM response_actions
        WHERE org_id=:org AND incident_id=:id AND state='executed' ''',org=org,id=key)}
    if 'restrict_test_account' in completed and 'restore_test_account' not in completed:
        raise HTTPException(409,'Record successful account restoration before closing the incident')
    run(conn, "UPDATE incidents SET status='closed',resolution=:body WHERE org_id=:org AND id=:id", org=org, id=key, body=body.body)
    set_monitoring(conn, org, key, False)
    audit(conn, org, user['id'], 'incident.closed', key)
    return {'ok':True}

@app.get('/api/responses')
def responses(user=Depends(member), conn=Depends(db, scope='function')):
    return rows(conn, 'SELECT * FROM response_actions WHERE org_id=:org ORDER BY created DESC,id LIMIT 100', org=user['org_id'])

@app.post('/api/incidents/{key}/responses/{action}', status_code=201)
def request_response(key: str, action: str, user=Depends(analyst), conn=Depends(db, scope='function')):
    org = user['org_id']
    record = lock_incident(conn, org, key)
    alert = required(one(conn, 'SELECT * FROM alerts WHERE org_id=:org AND id=:id', org=org,id=record['alert_id']))
    if record['status']=='closed' or action not in ('restrict_test_account','restore_test_account') or not (
        alert['simulated'] and alert['rule']=='auth_failure' and alert['asset']=='demo-test-account'):
        raise HTTPException(422, 'This incident is ineligible for DemoLab account actions')
    if action=='restore_test_account' and not one(conn, """SELECT id FROM response_actions WHERE org_id=:org
        AND incident_id=:id AND action='restrict_test_account' AND state='executed'""", org=org,id=key):
        raise HTTPException(409, 'Verify successful restriction before requesting restoration')
    response = identifier()
    stored = one(conn, """INSERT INTO response_actions VALUES (:id,:org,:incident,:integration,:action,
        'pending',:user,NULL,:created,NULL) ON CONFLICT(incident_id,action) DO UPDATE SET state='pending',
        requested_by=excluded.requested_by, approved_by=NULL, created=excluded.created
        WHERE response_actions.state='rejected' RETURNING id""",
        id=response, org=org, incident=key, integration=alert['integration_id'], action=action, user=user['id'], created=now())
    if not stored:
        raise HTTPException(409, 'An action of this type already exists for the incident')
    audit(conn, org, user['id'], 'response.requested', stored['id'])
    return {'id':stored['id']}

@app.post('/api/responses/{key}/{decision}')
def decide_response(key: str, decision: str, user=Depends(analyst), conn=Depends(db, scope='function')):
    if decision not in ('approve','reject'):
        raise HTTPException(404, 'Unknown decision')
    org = user['org_id']
    output = run(conn, """UPDATE response_actions SET state=:state,approved_by=:user
        WHERE org_id=:org AND id=:id AND state='pending'""",
        state='approved' if decision=='approve' else 'rejected', user=user['id'], org=org,id=key)
    if not output.rowcount:
        raise HTTPException(409, 'Pending response action unavailable')
    audit(conn, org, user['id'], 'response.'+decision, key)
    return {'ok':True}

@app.get('/api/connectors/{key}/actions')
def commands(item=Depends(connector), conn=Depends(db, scope='function')):
    return rows(conn, """SELECT id,action FROM response_actions WHERE org_id=:org AND integration_id=:id
        AND state='approved' ORDER BY created,id LIMIT 20""", org=item['org_id'],id=item['id'])

class Result(BaseModel):
    result: str = Field(regex=r'^(restricted|restored)$')

@app.post('/api/connectors/{key}/actions/{action_id}')
def response_result(action_id: str, body: Result, item=Depends(connector), conn=Depends(db, scope='function')):
    params = {'id':action_id, 'integration':item['id'], 'org':item['org_id']}
    action = required(one(conn, 'SELECT * FROM response_actions WHERE id=:id AND integration_id=:integration AND org_id=:org', **params))
    expected = 'restricted' if action['action']=='restrict_test_account' else 'restored'
    if body.result != expected or action['state'] not in ('approved','executed'):
        raise HTTPException(409, 'Result does not match an approved action')
    update = run(conn, """UPDATE response_actions SET state='executed',result=:result
        WHERE id=:id AND integration_id=:integration AND org_id=:org AND state='approved'""", result=expected, **params)
    if update.rowcount:
        status = 'contained' if expected=='restricted' else 'investigating'
        run(conn, "UPDATE incidents SET status=:status WHERE org_id=:org AND id=:id AND status!='closed'", status=status, org=item['org_id'],id=action['incident_id'])
        audit(conn, item['org_id'], item['id'], 'response.'+expected, action_id)
    return {'ok':True}

@app.get('/api/audit')
def audit_log(view: Literal['all', 'authentication'] = 'all', user=Depends(member), conn=Depends(db, scope='function')):
    return rows(conn, '''SELECT * FROM audit_logs WHERE org_id=:org
        AND (:view='all' OR action IN ('auth_success','auth_failure'))
        ORDER BY created DESC,id LIMIT 100''', org=user['org_id'], view=view)

@app.get('/api/health')
def health():
    return {'status':'ok'}

