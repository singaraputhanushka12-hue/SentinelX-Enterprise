import os
from importlib import import_module
from time import monotonic, sleep

import httpx
from fastapi.testclient import TestClient
from httpx import ConnectError

from database.schema import engine_for, password_hash
from login_portal import server as portal

from test_workflow import listen

enterprise = import_module('sentinelx-backend.app.main')
PASSWORD = 'isolated-portal-test-password'


def test_login_portal(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINELX_DATABASE_URL', 'sqlite:///' + (tmp_path / 'soc.sqlite3').as_posix())
    monkeypatch.setattr(enterprise, 'engine', engine_for('SENTINELX_DATABASE_URL', 'unused'))
    monkeypatch.setattr(portal, 'DATABASE', tmp_path / 'portal.sqlite3')
    monkeypatch.delenv('LOGIN_PORTAL_SIMULATED_IP', raising=False)
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    monkeypatch.delenv('SENTINELX_LLM_GATEWAY_URL', raising=False)

    # The restricted Windows test account cannot access DPAPI.
    def test_protection(value, encrypt):
        return b'test:' + value if encrypt else value.removeprefix(b'test:')

    if os.getenv('LOGIN_PORTAL_TEST_DPAPI') != '1':
        monkeypatch.setattr(portal, 'protect_data', test_protection)
    portal.initialize()
    with portal.database() as db:
        db.executemany('INSERT INTO accounts VALUES (?,?,?)',
                       [(name, password_hash(PASSWORD), admin)
                        for name, admin in [('admin', 1), ('demo', 0), ('outside', 0)]])

    unavailable = False
    post = portal.httpx.Client.post

    def post_event(client, url, **options):
        if unavailable and str(url).startswith(soc_url + '/api/connectors/'):
            raise ConnectError('Isolated outage')
        return post(client, url, **options)

    with (
        listen(enterprise.app) as soc_url,
        listen(portal.app, proxy_headers=False) as portal_url,
        httpx.Client(base_url=portal_url, timeout=5, trust_env=False) as browser,
        httpx.Client(base_url=portal_url, timeout=5, trust_env=False) as user,
    ):
        monkeypatch.setattr(portal.httpx.Client, 'post', post_event)
        monkeypatch.setenv('LOGIN_PORTAL_SENTINELX_URLS', soc_url)
        with httpx.Client(base_url=soc_url, timeout=5, trust_env=False) as soc:
            assert soc.post('/api/register', json={'organization': 'Isolated Portal', 'name': 'Portal Admin',
                'email': 'portal@example.test', 'password': PASSWORD, 'confirm': PASSWORD}).status_code == 201
            org = soc.get('/api/me').json()['org_id']
            created = soc.post('/api/integrations', json={'name': 'Customer login', 'kind': 'Login Portal'})
            assert created.status_code == 201
            credentials = created.json()
            path = f"/api/integrations/{credentials['id']}"
            body = {'url': soc_url, 'connector_id': credentials['id'], 'token': credentials['token']}

            def wait_for_failures(total):
                deadline = monotonic() + 8
                while monotonic() < deadline:
                    events = soc.get('/api/events?kind=auth_failure').json()
                    if len(events) == total:
                        return
                    sleep(.05)
                assert len(events) == total

            def login(client, name, password=PASSWORD):
                return client.post('/api/login-attempt', json={'username': name, 'password': password})

            assert browser.get('/').status_code == 200
            assert browser.get('/integration').status_code == 403
            assert browser.put('/api/integration', json=body).status_code == 403
            assert login(browser, 'admin').status_code == 200
            assert browser.get('/integration').status_code == 200
            assert browser.put('/api/integration', json={**body, 'token': 'x' * 43}).status_code == 400
            assert browser.put('/api/integration', json=body).json() == {'status': 'connected'}
            assert browser.post('/api/integration/test', json={}).status_code == 200
            assert soc.post(path + '/verify', json={}).status_code == 200
            assert credentials['token'] not in browser.get('/api/status').text

            assert login(user, 'demo').status_code == 200
            assert user.get('/integration').status_code == 403
            assert user.post('/api/logout', json={}).status_code == 200
            assert user.get('/api/session').json()['user'] is None
            rejected = user.post('/api/login-attempt', json={'username':'demo', 'password':'incorrect'},
                                 headers={'X-Forwarded-For':'192.0.2.10'})
            assert rejected.status_code == 401
            wait_for_failures(1)
            with portal.database() as local:
                recorded = local.execute("SELECT ip FROM attempts WHERE kind='auth_failure'").fetchone()
            assert recorded['ip'] == '127.0.0.1'
            audit_rows = soc.get('/api/audit').json()
            matches = [row for row in audit_rows if row['action'] == 'auth_failure']
            assert len(matches) == 1
            assert (matches[0]['actor'], matches[0]['target'], matches[0]['source_ip']) == (
                'demo', 'Customer login', recorded['ip'])
            assert any(row['action'] == 'integration.created' and row['source_ip'] is None for row in audit_rows)
            assert not soc.get('/api/alerts').json()

            # A standard connector in another organization keeps its five-failure threshold.
            with httpx.Client(base_url=soc_url, timeout=5, trust_env=False) as other:
                assert other.post('/api/register', json={'organization': 'Other Isolated Org', 'name': 'Other Admin',
                    'email': 'other-portal@example.test', 'password': PASSWORD, 'confirm': PASSWORD}).status_code == 201
                standard = other.post('/api/integrations', json={
                    'name': 'Other website', 'kind': 'Website / Web Application'}).json()
                for index in range(3):
                    assert other.post(f"/api/connectors/{standard['id']}/events",
                        headers={'Authorization': 'Bearer ' + standard['token']},
                        json={'external_id': f'standard-event-{index}', 'kind': 'auth_failure', 'asset': 'demo',
                              'occurred': enterprise.now(), 'simulated': True}).status_code == 202
                assert not other.get('/api/alerts').json()

            unavailable = True
            assert login(user, 'demo', 'incorrect').status_code == 401
            assert login(user, 'demo', 'incorrect').status_code == 401
            assert login(user, 'demo').status_code == 200
            assert browser.post('/api/integration/test', json={}).status_code == 503
            assert not soc.get('/api/alerts').json()
            unavailable = False
            wait_for_failures(3)
            alerts = soc.get('/api/alerts').json()
            assert len(alerts) == 1
            auth = soc.get('/api/audit?view=authentication').json()
            assert all(row['action'] in ('auth_success', 'auth_failure') for row in auth)
            failures = [row for row in auth if row['action'] == 'auth_failure']
            assert len(failures) == 3
            assert {row['source_ip'] for row in failures} == {'127.0.0.1'}
            events = soc.get('/api/events?kind=auth_failure').json()
            with portal.database() as local:
                local_attempts = {
                    row['id']: (row['ip'], row['occurred'])
                    for row in local.execute("SELECT id,ip,occurred FROM attempts WHERE kind='auth_failure'")
                }
            audit_by_id = {row['id']: row for row in failures}
            assert set(audit_by_id) == {event['id'] for event in events}
            assert [row['created'] for row in auth] == sorted((row['created'] for row in auth), reverse=True)
            for event in events:
                address, occurred = local_attempts[event['external_id']]
                assert event['occurred'] == occurred
                assert (audit_by_id[event['id']]['source_ip'], audit_by_id[event['id']]['created']) == (address, occurred)
            assert any(row['action'] == 'integration.created' for row in soc.get('/api/audit?view=all').json())
            alert = alerts[0]
            assert alert['label'] == 'Repeated Failed Login Attempts'
            assert alert['severity'] == 'high'
            assert alert['reason'] == enterprise.PORTAL_REASON
            assert len(alert['recommended_actions']) == 6
            assert len(alert['evidence']) == 3
            incidents = soc.get('/api/incidents').json()
            assert len(incidents) == 1 and incidents[0]['alert_id'] == alert['id']
            case_path = f"/api/incidents/{incidents[0]['id']}"
            assert soc.get(case_path).json()['summary'] == alert['reason']

            with portal.database() as db:
                db.execute("""UPDATE attempts SET delivery='pending' WHERE id=(
                    SELECT id FROM attempts WHERE kind='auth_failure' AND username='demo' ORDER BY rowid LIMIT 1)""")
            portal.deliver()
            assert len(soc.get('/api/events?kind=auth_failure').json()) == 3
            assert login(user, 'demo', 'incorrect').status_code == 401
            wait_for_failures(4)
            assert len(soc.get('/api/alerts').json()) == 1

            original_now = enterprise.now
            monkeypatch.setattr(enterprise, 'now', lambda: original_now() - 121)
            endpoint = f"/api/connectors/{credentials['id']}/events"
            header = {'Authorization': 'Bearer ' + body['token']}
            for index in range(2):
                event = {'external_id': f'old-event-{index}', 'kind': 'auth_failure', 'asset': 'outside',
                         'occurred': enterprise.now(), 'simulated': True}
                assert soc.post(endpoint, headers=header, json=event).status_code == 202
            monkeypatch.setattr(enterprise, 'now', original_now)
            assert login(user, 'outside', 'incorrect').status_code == 401
            wait_for_failures(7)
            assert len(soc.get('/api/alerts').json()) == 1

            with TestClient(portal.app, client=('unknown-peer', 0)) as no_peer:
                assert login(no_peer, 'missing-peer', 'incorrect').status_code == 401
            wait_for_failures(8)
            monkeypatch.setenv('LOGIN_PORTAL_SIMULATED_IP', '192.0.2.10')
            with TestClient(portal.app, client=('unknown-peer', 0)) as no_peer:
                assert login(no_peer, 'simulated-peer', 'incorrect').status_code == 401
            with TestClient(portal.app, client=('::1', 0)) as ipv6:
                assert login(ipv6, 'ipv6-peer', 'incorrect').status_code == 401
            wait_for_failures(10)
            auth_by_actor = {row['actor']: row for row in soc.get('/api/audit?view=authentication').json()}
            assert (auth_by_actor['missing-peer']['source_ip'], auth_by_actor['missing-peer']['source_ip_simulated']) == (None, 0)
            assert (auth_by_actor['simulated-peer']['source_ip'], auth_by_actor['simulated-peer']['source_ip_simulated']) == ('192.0.2.10', 1)
            assert (auth_by_actor['ipv6-peer']['source_ip'], auth_by_actor['ipv6-peer']['source_ip_simulated']) == ('::1', 0)
            assert all(row['source_ip'] is None and row['source_ip_simulated'] == 0
                       for row in soc.get('/api/audit?view=all').json()
                       if row['action'] not in ('auth_success','auth_failure'))
            marked_event = {'external_id':'invalid-demo-marker','kind':'auth_failure','asset':'demo',
                            'occurred':enterprise.now(),'source_ip':'192.0.2.10','source_ip_simulated':True}
            assert soc.post(endpoint, headers=header, json=marked_event).status_code == 422

            rotated = soc.post(path + '/rotate', json={}).json()
            assert browser.post('/api/integration/test', json={}).status_code == 400
            assert browser.put('/api/integration', json={**body, 'token': rotated['token']}).status_code == 200
            assert browser.post('/api/integration/disconnect', json={}).status_code == 200
            assert browser.get('/api/status').json()['status'] == 'disconnected'

            deadline = monotonic() + 10
            while monotonic() < deadline:
                ai = soc.get(case_path + '/ai-evidence').json()
                if ai['monitor']['state'] == 'failed':
                    break
                sleep(.1)
            assert ai['monitor']['state'] == 'failed'
            assert ai['saved'] is None

            # Exercise the authorized provider path through the existing worker.
            monkeypatch.setenv('OPENAI_API_KEY', 'test-only')
            monkeypatch.setenv('SENTINELX_AI_ALLOWED_ORGS', org)
            report_module = import_module('sentinelx-backend.app.investigations.report')

            def provider_fixture(packet):
                ids = [event['id'] for event in packet['events']]
                assert set(alert['evidence']) <= set(ids)
                return ({section: {'text': 'Isolated provider fixture.', 'event_ids': ids}
                         for section in report_module.SECTIONS}, 'test-model', {})

            monkeypatch.setattr(report_module, 'openai_report', provider_fixture)
            with enterprise.engine.begin() as db:
                enterprise.run(db, 'UPDATE ai_investigation_sessions SET next_check=0 WHERE org_id=:org', org=org)
            deadline = monotonic() + 10
            while monotonic() < deadline:
                ai = soc.get(case_path + '/ai-evidence').json()
                if ai['saved']:
                    break
                sleep(.1)
            assert ai['saved']['report']['provider'] == 'OpenAI'
