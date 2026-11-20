import os
import re
import secrets
import threading
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from database.schema import digest, engine_for, identifier, initialize, now, one, password_hash, password_matches, rows, run
from service_common import ApiBoundary

engine = engine_for('DEMOLAB_DATABASE_URL', 'demolab.sqlite3')
ENTERPRISE = os.getenv('DEMOLAB_ENTERPRISE_URL', 'http://127.0.0.1:8001').rstrip('/')
COOKIE = 'demolab_session'
ACCOUNT = 'demo-test-account'
LOCK = threading.Lock()
SCENARIOS = {
    'failed-login': ('auth_failure', ACCOUNT, 5),
    'web-signal': ('web_signal', 'demo-web', 1),
    'request-volume': ('request_burst', 'demo-web', 3),
    'application-errors': ('app_error', 'demo-app', 3),
    'service-unavailable': ('service_unavailable', 'demo-health', 1),
    'api-denied': ('api_denied', 'demo-api', 3),
}
TABLES = [
    "CREATE TABLE administrators (id INTEGER PRIMARY KEY CHECK(id=1), password TEXT NOT NULL)",
    "CREATE TABLE lab_sessions (token VARCHAR(64) PRIMARY KEY, expires BIGINT NOT NULL)",
    "CREATE TABLE configuration (id INTEGER PRIMARY KEY CHECK(id=1), connector TEXT NOT NULL, token TEXT NOT NULL)",
    "CREATE TABLE test_account (id INTEGER PRIMARY KEY CHECK(id=1), restricted_until BIGINT NOT NULL, last_scenario BIGINT NOT NULL)",
    "INSERT INTO test_account VALUES (1,0,0)",
    """CREATE TABLE activity (id VARCHAR(64) PRIMARY KEY, kind TEXT NOT NULL, asset TEXT NOT NULL,
        created BIGINT NOT NULL, enterprise_id TEXT, state TEXT NOT NULL)""",
    "CREATE TABLE applied_actions (id VARCHAR(64) PRIMARY KEY, result TEXT NOT NULL)",
]
PORTAL_TABLES = [
    """CREATE TABLE sample_transactions (id VARCHAR(24) PRIMARY KEY, counterparty TEXT NOT NULL,
        amount_cents INTEGER NOT NULL, status VARCHAR(24) NOT NULL)""",
    """INSERT INTO sample_transactions VALUES ('DL-1001','Northline Supplies',32500,'Settled'),
        ('DL-1002','Juniper Studio',18950,'Pending'), ('DL-1003','Atlas Services',8500,'Settled')""",
]

@asynccontextmanager
async def lifespan(_app):
    initialize(engine, TABLES, PORTAL_TABLES)
    yield

app = FastAPI(title='SentinelX DemoLab', lifespan=lifespan)

app.add_middleware(ApiBoundary, prefix='/lab/', origin_setting='DEMOLAB_ORIGINS',
                   default_origins='http://127.0.0.1:5175,http://localhost:5175', max_body=8192)

def require_admin(request: Request):
    with engine.begin() as conn:
        authorized = one(conn, 'SELECT token FROM lab_sessions WHERE token=:token AND expires>:time',
                         token=digest(request.cookies.get(COOKIE,'')), time=now())
    if not authorized:
        raise HTTPException(401, 'Sign in as DemoLab administrator')

class Password(BaseModel):
    password: str = Field(min_length=12,max_length=128)

@app.get('/lab/setup')
def setup_required():
    with engine.begin() as conn:
        return {'required': not one(conn,'SELECT id FROM administrators')}

@app.post('/lab/setup', status_code=201)
def setup(body: Password, response: Response):
    with engine.begin() as conn:
        result = run(conn, 'INSERT INTO administrators VALUES (1,:password) ON CONFLICT(id) DO NOTHING',
                     password=password_hash(body.password))
        if not result.rowcount:
            raise HTTPException(409,'DemoLab already has an administrator')
        establish(conn,response)
    return {'ok':True}

def establish(conn, response):
    token=secrets.token_urlsafe(32)
    run(conn,'INSERT INTO lab_sessions VALUES (:token,:expires)',token=digest(token),expires=now()+86400)
    response.set_cookie(COOKIE,token,httponly=True,samesite='strict',max_age=86400,
                        secure=os.getenv('DEMOLAB_SECURE_COOKIES')=='1')

@app.post('/lab/login')
def login(body: Password, response: Response):
    with engine.begin() as conn:
        account = one(conn,'SELECT password FROM administrators WHERE id=1')
        if not account or not password_matches(body.password,account['password']):
            raise HTTPException(401,'Invalid password')
        establish(conn,response)
    return {'ok':True}

@app.post('/lab/logout')
def logout(request: Request, response: Response):
    with engine.begin() as conn:
        run(conn,'DELETE FROM lab_sessions WHERE token=:token',token=digest(request.cookies.get(COOKIE,'')))
    response.delete_cookie(COOKIE)
    return {'ok':True}

class Configuration(BaseModel):
    connector: str = Field(regex=r'^[a-f0-9]{32}$')
    token: str = Field(regex=r'^[A-Za-z0-9_-]{43}$')

def call(config, method, path, body=None):
    try:
        with httpx.Client(timeout=2, follow_redirects=False, trust_env=False) as client:
            response=client.request(method, f"{ENTERPRISE}/api/connectors/{config['connector']}/{path}",
                                    headers={'Authorization':'Bearer '+config['token']},json=body)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code==409 and path=='events':
            return {'id':None}
        raise HTTPException(502, f'Enterprise rejected the connector request (HTTP {exc.response.status_code})')
    except httpx.HTTPError:
        raise HTTPException(502,'Enterprise API is unavailable')

def config_for(conn):
    config=one(conn,'SELECT connector,token FROM configuration WHERE id=1')
    if not config:
        raise HTTPException(409,'Configure a connector first')
    return config

def publish(config, kind, asset):
    key, created = identifier(), now()
    with engine.begin() as conn:
        run(conn,"INSERT INTO activity VALUES (:id,:kind,:asset,:created,NULL,'queued')",
            id=key,kind=kind,asset=asset,created=created)
    try:
        result=call(config,'POST','events',{'external_id':key,'kind':kind,'asset':asset,'occurred':created,'simulated':True})
    except HTTPException:
        with engine.begin() as conn:
            run(conn,"UPDATE activity SET state='failed' WHERE id=:id",id=key)
        raise
    with engine.begin() as conn:
        run(conn,"UPDATE activity SET state='delivered',enterprise_id=:event WHERE id=:id",id=key,event=result['id'])
    return result

@app.post('/lab/connector', dependencies=[Depends(require_admin)])
def configure(body: Configuration):
    config=body.dict()
    with LOCK:
        result=publish(config,'connector_check','demolab')
        with engine.begin() as conn:
            run(conn,'''INSERT INTO configuration VALUES (1,:connector,:token)
                 ON CONFLICT(id) DO UPDATE SET connector=excluded.connector,token=excluded.token''',**config)
    return result

@app.post('/lab/scenarios/{scenario}', dependencies=[Depends(require_admin)])
def scenario(scenario: str):
    definition=SCENARIOS.get(scenario)
    if not definition:
        raise HTTPException(404,'Unknown scenario')
    kind,asset,count=definition
    if not LOCK.acquire(blocking=False):
        raise HTTPException(409,'An operation is already running')
    try:
        with engine.begin() as conn:
            config=config_for(conn)
            result=run(conn,'''UPDATE test_account SET last_scenario=:time WHERE id=1
                AND last_scenario<=:cutoff AND (:kind!='auth_failure' OR restricted_until<=:time)''',
                       time=now(),cutoff=now()-10,kind=kind)
            if not result.rowcount:
                raise HTTPException(409,'Wait for the scenario cooldown or restore the test account')
        return {'events':[publish(config,kind,asset) for _ in range(count)]}
    finally:
        LOCK.release()

@app.post('/lab/sync', dependencies=[Depends(require_admin)])
def sync():
    with LOCK:
        with engine.begin() as conn:
            config=config_for(conn)
        commands=call(config,'GET','actions')
        confirmed=[]
        for command in commands:
            key, action=command['id'],command['action']
            if not re.fullmatch(r'[a-f0-9]{32}',key) or action not in ('restrict_test_account','restore_test_account'):
                continue
            restricted=action=='restrict_test_account'
            with engine.begin() as conn:
                existing=one(conn,'SELECT result FROM applied_actions WHERE id=:id',id=key)
                result='restricted' if restricted else 'restored'
                if existing:
                    result=existing['result']
                else:
                    run(conn,'UPDATE test_account SET restricted_until=:until WHERE id=1',until=now()+300 if restricted else 0)
                    run(conn,'INSERT INTO applied_actions VALUES (:id,:result)',id=key,result=result)
                    run(conn,"INSERT INTO activity VALUES (:id,:kind,:asset,:created,NULL,'applied')",
                        id=key,kind=result,asset=ACCOUNT,created=now())
            call(config,'POST','actions/'+key,{'result':result})
            confirmed.append(result)
        return {'confirmed':confirmed}

@app.get('/lab/status', dependencies=[Depends(require_admin)])
def status():
    with engine.begin() as conn:
        account=one(conn,'SELECT restricted_until FROM test_account WHERE id=1')
        config=one(conn,'SELECT connector FROM configuration WHERE id=1')
        return {'connected':bool(config),'restricted':account['restricted_until']>now(),'account':ACCOUNT,
                'activity':rows(conn,'SELECT * FROM activity ORDER BY created DESC,id LIMIT 50')}

@app.get('/lab/sample-portal', dependencies=[Depends(require_admin)])
def sample_portal():
    with engine.begin() as conn:
        account=one(conn,'SELECT restricted_until FROM test_account WHERE id=1')
        if account['restricted_until']>now():
            raise HTTPException(423,'Test account access is temporarily restricted')
        return {'account':ACCOUNT,'transactions':rows(conn,'SELECT * FROM sample_transactions ORDER BY id')}

@app.get('/lab/health')
def health():
    return {'status':'ok'}

