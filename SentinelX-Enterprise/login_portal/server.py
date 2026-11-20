import asyncio
import logging
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager, closing, contextmanager
from getpass import getpass
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from database.schema import digest, identifier, now, password_hash, password_matches
from service_common import ApiBoundary
from .credentials import protect_data

ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.getenv('LOGIN_PORTAL_DB', ROOT.parent / 'database' / 'login-portal.sqlite3'))
COOKIE = 'sentinelx_portal_session'
SESSION_SECONDS = 8 * 3600
SECURE_COOKIES = os.getenv('LOGIN_PORTAL_SECURE_COOKIES') == '1'


@contextmanager
def database():
    with closing(sqlite3.connect(DATABASE, timeout=5)) as conn:
        conn.row_factory = sqlite3.Row
        with conn:
            yield conn


def initialize():
    with database() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (username TEXT PRIMARY KEY, password TEXT NOT NULL, admin INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, username TEXT NOT NULL, ip TEXT NOT NULL,
                occurred INTEGER NOT NULL, kind TEXT NOT NULL, target TEXT, delivery TEXT NOT NULL,
                simulated_ip TEXT);
            CREATE INDEX IF NOT EXISTS attempts_time ON attempts(occurred);
            CREATE TABLE IF NOT EXISTS connector (id INTEGER PRIMARY KEY CHECK(id=1), url TEXT NOT NULL,
                connector_id TEXT NOT NULL, secret BLOB NOT NULL, revision TEXT NOT NULL, status TEXT NOT NULL);
        """)

        conn.execute('BEGIN IMMEDIATE')
        if not any(column['name'] == 'simulated_ip' for column in conn.execute('PRAGMA table_info(attempts)')):
            conn.execute('ALTER TABLE attempts ADD COLUMN simulated_ip TEXT')


def client_address(host):
    try:
        # A scope identifies the local interface, rather than part of an IPv6 address.
        return str(ip_address(host.split('%', 1)[0]))
    except ValueError:
        return None


def connection(conn):
    return conn.execute('SELECT * FROM connector WHERE id=1').fetchone()


def event_target(config):
    return digest(config['url'] + '/' + config['connector_id'])


def send_event(url, key, token, event):
    try:
        with httpx.Client(timeout=2, trust_env=False) as client:
            result = client.post(f'{url}/api/connectors/{key}/events', json=event,
                                 headers={'Authorization': f'Bearer {token}'})
    except httpx.RequestError:
        return 'unavailable'
    if result.status_code == 202 and event['kind'] == 'connector_check':
        try:
            if result.json().get('integration_kind') != 'Login Portal':
                return 'wrong_kind'
        except (ValueError, AttributeError):
            return 'unavailable'
    return {202: 'connected', 409: 'duplicate', 401: 'credentials_rejected',
            429: 'rate_limited', 422: 'rejected'}.get(result.status_code, 'unavailable')


def deliver():
    with database() as conn:
        conn.execute("UPDATE attempts SET delivery='expired' WHERE delivery='pending' AND occurred<?", (now()-120,))
        config = connection(conn)
        if not config:
            return
        pending = conn.execute("""SELECT * FROM attempts WHERE target=? AND delivery='pending'
            ORDER BY occurred,rowid LIMIT 20""", (event_target(config),)).fetchall()
    if not pending:
        return
    try:
        token = protect_data(config['secret'], False).decode()
    except OSError:
        update_status(config, 'credentials_rejected')
        return
    for attempt in pending:
        event = {
            'external_id': attempt['id'], 'kind': attempt['kind'], 'asset': attempt['username'],
            'occurred': attempt['occurred'], 'simulated': True,
        }
        source_ip = client_address(attempt['ip'])
        if source_ip:
            event['source_ip'] = source_ip
        elif attempt['simulated_ip']:
            event.update(source_ip=attempt['simulated_ip'], source_ip_simulated=True)
        result = send_event(config['url'], config['connector_id'], token, event)
        if result in ('unavailable', 'rate_limited', 'credentials_rejected'):
            update_status(config, result)
            return
        with database() as conn:
            conn.execute("UPDATE attempts SET delivery=? WHERE id=? AND delivery='pending'",
                         ('delivered' if result in ('connected', 'duplicate') else result, attempt['id']))
        if result in ('connected', 'duplicate'):
            update_status(config, 'connected')


def update_status(config, status):
    with database() as conn:
        conn.execute('UPDATE connector SET status=? WHERE revision=?', (status, config['revision']))


async def delivery_worker():
    while True:
        try:
            await run_in_threadpool(deliver)
        except sqlite3.Error:
            logging.getLogger(__name__).exception('Portal event queue could not be processed')
        await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(_app):
    initialize()
    worker = asyncio.create_task(delivery_worker())
    try:
        yield
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)


app = FastAPI(title='SentinelX Login Portal', lifespan=lifespan)
app.add_middleware(ApiBoundary, prefix='/api/', origin_setting='LOGIN_PORTAL_ORIGINS',
                   default_origins='http://127.0.0.1:5500,http://localhost:5500', max_body=8192)


@app.exception_handler(RequestValidationError)
async def invalid_input(_request, _error):
    return JSONResponse({'detail': 'Check the fields and try again.'}, status_code=422)


class Login(BaseModel):
    username: str = Field(regex=r'^[a-zA-Z0-9_.-]{1,100}$')
    password: str = Field(min_length=1, max_length=128)


class Connector(BaseModel):
    url: str = Field(min_length=1, max_length=500)
    connector_id: str = Field(regex=r'^[a-f0-9]{32}$')
    token: str = Field(regex=r'^[a-zA-Z0-9_-]{43}$')


def authorized_url(value):
    url = value.strip().rstrip('/')
    try:
        parsed = urlsplit(url)
        allowed = set(os.getenv('LOGIN_PORTAL_SENTINELX_URLS', 'http://127.0.0.1:8003,http://localhost:8003').split(','))
        if (url in allowed and parsed.hostname and parsed.netloc and not
                (parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment)
                and (parsed.scheme == 'https' or
                     (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')))):
            return url
    except ValueError:
        pass
    raise HTTPException(422, 'Use an approved SentinelX API URL.')


def current_user(request: Request):
    with database() as conn:
        return conn.execute("""SELECT a.username,a.admin FROM sessions s JOIN accounts a ON s.username=a.username
            WHERE s.token=? AND s.expires>?""", (digest(request.cookies.get(COOKIE, '')), now())).fetchone()


def require_admin(user=Depends(current_user)):
    if not user or not user['admin']:
        raise HTTPException(403, 'Sign in with a portal administrator account.')
    return user


@app.get('/api/session')
def session(user=Depends(current_user)):
    return {'user': dict(user) if user else None}


@app.get('/api/status')
def status():
    with database() as conn:
        config = connection(conn)
    return {'status': config['status'] if config else 'disconnected'}


@app.post('/api/login-attempt')
def login(body: Login, request: Request, response: Response):
    username = body.username.lower()
    # The ASGI server resolves the peer using explicit proxy settings.
    ip = client_address(request.client.host) if request.client else None
    simulated_ip = None
    if ip is None and os.getenv('LOGIN_PORTAL_SIMULATED_IP') == '192.0.2.10':
        simulated_ip = '192.0.2.10'
    ip = ip or ''
    stamp = now()
    with database() as conn:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('DELETE FROM attempts WHERE occurred<?', (stamp-86400,))
        conn.execute('DELETE FROM sessions WHERE expires<=?', (stamp,))
        counts = conn.execute("""SELECT COUNT(CASE WHEN ip=? THEN 1 END),
            COUNT(CASE WHEN username=? THEN 1 END) FROM attempts WHERE occurred>?""",
                              (ip, username, stamp-120)).fetchone()
        if counts[0] >= 30 or counts[1] >= 8:
            raise HTTPException(429, 'Too many attempts. Try again in two minutes.', headers={'Retry-After': '120'})
        account = conn.execute('SELECT * FROM accounts WHERE username=?', (username,)).fetchone()
        stored = account['password'] if account else '0' * 32 + ':' + '0' * 128
        valid = password_matches(body.password, stored) and account is not None
        kind = 'auth_success' if valid else 'auth_failure'
        config = connection(conn)
        conn.execute('''INSERT INTO attempts (id,username,ip,occurred,kind,target,delivery,simulated_ip)
            VALUES (?,?,?,?,?,?,?,?)''',
                     (identifier(), username, ip, stamp, kind, event_target(config) if config else None,
                      'pending' if config else 'local', simulated_ip))
        if valid:
            token = secrets.token_urlsafe(32)
            conn.execute('DELETE FROM sessions WHERE token=?', (digest(request.cookies.get(COOKIE, '')),))
            conn.execute('INSERT INTO sessions VALUES (?,?,?)', (digest(token), username, stamp+SESSION_SECONDS))
    if not valid:
        raise HTTPException(401, 'Invalid username or password.')
    response.set_cookie(COOKIE, token, httponly=True, samesite='strict',
                        secure=SECURE_COOKIES, max_age=SESSION_SECONDS)
    return {'user': {'username': username, 'admin': account['admin']}}


@app.post('/api/logout')
def logout(request: Request, response: Response):
    with database() as conn:
        conn.execute('DELETE FROM sessions WHERE token=?', (digest(request.cookies.get(COOKIE, '')),))
    response.delete_cookie(COOKIE, httponly=True, samesite='strict', secure=SECURE_COOKIES)
    return {'ok': True}


def check(url, key, token):
    return send_event(url, key, token, {
        'external_id': identifier(), 'kind': 'connector_check', 'asset': 'login-portal',
        'occurred': now(), 'simulated': True,
    })


def check_result(result):
    messages = {
        'credentials_rejected': (400, 'SentinelX rejected the connector ID and token. Check the API URL and use the current token.'),
        'rate_limited': (429, 'SentinelX rate limited the connection test. Try again shortly.'),
        'wrong_kind': (400, 'Use a SentinelX connector created with the Login Portal type.'),
        'unavailable': (503, 'SentinelX is unavailable. Check the API URL and service.'),
    }
    if result != 'connected':
        code, message = messages.get(result, (400, 'SentinelX rejected the connection test.'))
        raise HTTPException(code, message)


@app.put('/api/integration')
def connect(body: Connector, _user=Depends(require_admin)):
    url = authorized_url(body.url)
    check_result(check(url, body.connector_id, body.token))
    try:
        encrypted = protect_data(body.token.encode(), True)
    except (OSError, RuntimeError):
        raise HTTPException(503, 'Windows could not protect the connector token. Run the portal under your signed-in Windows account.') from None
    with database() as conn:
        conn.execute("""INSERT INTO connector VALUES (1,?,?,?,?,'connected')
            ON CONFLICT(id) DO UPDATE SET url=excluded.url, connector_id=excluded.connector_id,
            secret=excluded.secret, revision=excluded.revision, status=excluded.status""",
                     (url, body.connector_id, encrypted, identifier()))
    return {'status': 'connected'}


@app.post('/api/integration/test')
def test_connection(_user=Depends(require_admin)):
    with database() as conn:
        config = connection(conn)
    if not config:
        raise HTTPException(409, 'Connect to SentinelX first.')
    try:
        token = protect_data(config['secret'], False).decode()
    except OSError:
        raise HTTPException(409, 'Update the stored connector credentials.') from None
    result = check(config['url'], config['connector_id'], token)
    update_status(config, result)
    check_result(result)
    return {'status': result}


@app.post('/api/integration/disconnect')
def disconnect(_user=Depends(require_admin)):
    with database() as conn:
        conn.execute('DELETE FROM connector')
        conn.execute("UPDATE attempts SET delivery='disconnected' WHERE delivery='pending'")
    return {'status': 'disconnected'}


@app.get('/')
def home():
    return FileResponse(ROOT / 'index.html')


@app.get('/integration')
def integration_page(_user=Depends(require_admin)):
    return FileResponse(ROOT / 'integration.html', headers={'Cache-Control': 'no-store'})


@app.get('/assets/{asset}')
def static_asset(asset: str):
    if asset not in ('style.css', 'script.js'):
        raise HTTPException(404)
    return FileResponse(ROOT / asset)


def initialize_demo():
    if os.getenv('LOGIN_PORTAL_DEVELOPMENT') != '1':
        raise SystemExit('Enable LOGIN_PORTAL_DEVELOPMENT=1 for demo account initialization.')
    accounts = []
    for username, admin in [('admin', 1), ('demo', 0)]:
        password = getpass(f'Create password for {username} (12–128 characters): ')
        if not 12 <= len(password) <= 128 or password != getpass('Confirm password: '):
            raise SystemExit('Passwords must match and contain 12–128 characters.')
        accounts.append((username, password_hash(password), admin))
    initialize()
    with database() as conn:
        conn.executemany('INSERT INTO accounts VALUES (?,?,?) ON CONFLICT(username) DO NOTHING', accounts)
    print('Demo accounts initialized. Existing accounts retain their passwords.')


if __name__ == '__main__':
    import sys

    if sys.argv[1:] != ['init-demo']:
        raise SystemExit('Usage: python -m login_portal.server init-demo')
    initialize_demo()
