import json
import os
import socket
from contextlib import contextmanager
from importlib import import_module
from threading import Thread
from time import monotonic, sleep, time

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from database.schema import engine_for, identifier, run

enterprise = import_module('sentinelx-backend.app.main')
from demolab.backend import main as demo

PASSWORD = 'separate-local-password'

@contextmanager
def listen(app, **options):
    with socket.socket() as binding:
        binding.bind(('127.0.0.1', 0))
        port = binding.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level='warning', timeout_graceful_shutdown=2, **options))
        worker = Thread(target=server.run, kwargs={'sockets':[binding]}, daemon=True)
        worker.start()
        try:
            deadline = monotonic() + 10
            while not server.started and worker.is_alive() and monotonic() < deadline:
                sleep(.03)
            assert server.started
            yield f'http://127.0.0.1:{port}'
        finally:
            server.should_exit = True
            worker.join(5)
            assert not worker.is_alive()

@contextmanager
def clients(network, monkeypatch):
    if network:
        with listen(enterprise.app) as enterprise_url, listen(demo.app) as lab_url:
            monkeypatch.setattr(demo, 'ENTERPRISE', enterprise_url)
            with httpx.Client(base_url=enterprise_url, timeout=5, trust_env=False) as soc, \
                 httpx.Client(base_url=enterprise_url, timeout=5, trust_env=False) as other, \
                 httpx.Client(base_url=lab_url, timeout=5, trust_env=False) as lab:
                yield soc, other, lab
        return
    with TestClient(enterprise.app) as soc, TestClient(enterprise.app) as other, TestClient(demo.app) as lab:
        # Bridge only the transport. DemoLab still sends authenticated API requests.
        class APIBridge:
            def __init__(self, **_options):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_exception):
                return False

            def request(self, method, url, **options):
                return soc.request(method, url.removeprefix(demo.ENTERPRISE), **options)

        with monkeypatch.context() as mock:
            mock.setattr(demo.httpx, 'Client', APIBridge)
            yield soc, other, lab

@pytest.mark.parametrize('network', [
    False, pytest.param(True, marks=pytest.mark.skipif(os.getenv('SENTINELX_TEST_HTTP') != '1',
                                                      reason='Set SENTINELX_TEST_HTTP=1 for loopback servers'))
])
def test_detection_to_response(tmp_path, monkeypatch, network):
    monitor = import_module('sentinelx-backend.app.investigations.monitor')

    async def idle_worker():
        pass

    monkeypatch.setattr(enterprise, 'monitor_investigations', idle_worker)
    monkeypatch.setenv('SENTINELX_DATABASE_URL', 'sqlite:///' + (tmp_path/'enterprise.sqlite3').as_posix())
    monkeypatch.setenv('DEMOLAB_DATABASE_URL', 'sqlite:///' + (tmp_path/'demolab.sqlite3').as_posix())
    monkeypatch.setattr(enterprise, 'engine', engine_for('SENTINELX_DATABASE_URL', 'unused'))
    monkeypatch.setattr(demo, 'engine', engine_for('DEMOLAB_DATABASE_URL', 'unused'))

    with clients(network, monkeypatch) as (soc, other, lab):
        def register(client, number):
            response = client.post('/api/register', json={'organization':f'Workspace {number}', 'name':'Test Analyst',
                'email':f'test{number}@example.test','password':PASSWORD,'confirm':PASSWORD})
            assert response.status_code == 201, response.text
            assert response.json() == {'onboarded': False}
            return client.get('/api/me').json()['org_id']

        assert soc.get('/api/me').status_code == 401
        assert lab.post('/lab/scenarios/failed-login', json={}).status_code == 401
        assert register(soc, 1) != register(other, 2)
        creds_response = soc.post('/api/integrations', json={'name':'Customer portal','kind':'Website / Web Application'})
        assert creds_response.status_code == 201, creds_response.text
        creds = creds_response.json()
        key = creds['id']
        route = f'/api/integrations/{key}'
        events_route = f'/api/connectors/{key}/events'
        assert other.get('/api/integrations').json() == []
        assert other.post(route+'/rotate', json={}).status_code == 404
        assert 'token' not in soc.get('/api/integrations').json()[0]
        assert soc.post(route+'/verify', json={}).status_code == 409
        assert soc.post(events_route, json={}).status_code == 401
        header = {'Authorization':'Bearer '+creds['token']}
        stale = {'external_id':identifier(),'kind':'health_check','asset':'portal','occurred':int(time())-500}
        assert soc.post(events_route, json=stale, headers=header).status_code == 422
        assert lab.post('/lab/setup', json={'password':PASSWORD}).status_code == 201
        configured = lab.post('/lab/connector', json={'connector':key,'token':creds['token']})
        assert configured.status_code == 200, configured.text
        assert soc.post(route+'/verify', json={}).status_code == 200
        assert soc.get('/api/me').json()['onboarded'] == 1
        assert soc.get('/api/overview').json()['totals']['integrations'] == 1
        event = soc.get('/api/events').json()[0]
        assert event['kind'] == 'connector_check' and event['simulated'] == 1
        replay = {name:event[name] for name in ('external_id','kind','asset','occurred')}
        assert soc.post(events_route, json=replay, headers=header).status_code == 409
        assert other.get('/api/events/'+event['id']).status_code == 404
        assert other.get('/api/events').json() == []
        from starlette.requests import Request
        request = Request({'type':'http','headers':[(b'cookie',f"{enterprise.COOKIE}={soc.cookies.get(enterprise.COOKIE)}".encode())]})
        assert enterprise.snapshot(request)[0]['id'] == event['id']
        if network:
            with soc.stream('GET','/api/live') as stream:
                assert stream.status_code == 200
                line = next(stream.iter_lines())
                assert json.loads(line.removeprefix('data: '))[0]['id'] == event['id']

        scenario = lab.post('/lab/scenarios/failed-login', json={})
        assert scenario.status_code == 200, scenario.text
        assert len(scenario.json()['events']) == 5
        assert lab.post('/lab/scenarios/failed-login', json={}).status_code == 409
        alert, = soc.get('/api/alerts').json()
        assert alert['rule'] == 'auth_failure'
        assert len(alert['evidence']) == 5 and alert['simulated'] == 1
        assert other.get('/api/alerts').json() == []
        alert_path = '/api/alerts/'+alert['id']+'/incident'
        assert other.post(alert_path, json={}).status_code == 404
        incident_response = soc.post(alert_path, json={})
        assert incident_response.status_code == 201, incident_response.text
        incident = incident_response.json()['id']
        path = '/api/incidents/'+incident
        assert other.get(path).status_code == 404
        assert other.get(path+'/ai-evidence').status_code == 404
        assert other.post(path+'/ai-monitor', json={'active': False}).status_code == 404
        assert soc.get(path+'/ai-evidence').json()['monitor']['state'] == 'starting'
        assert other.post(path+'/ai-report',json={'mode':'full'}).status_code == 404
        evidence = soc.get(path+'/ai-evidence').json()['evidence']
        assert len(evidence['events']) == 5
        assert evidence['alert']['id'] == alert['id']
        extra = {'external_id':identifier(),'kind':'auth_failure','asset':alert['asset'],
                 'occurred':int(time()),'simulated':True}
        latest = soc.post(events_route,json=extra,headers=header)
        assert latest.status_code == 202
        fresh = soc.get(path+'/ai-evidence').json()['evidence']
        assert latest.json()['id'] in {event['id'] for event in fresh['events']}
        owner_org=soc.get('/api/me').json()['org_id']
        with monkeypatch.context() as mock:
            def mock_generate(org, packet, mode):
                assert org==owner_org and packet['alert']['id']==alert['id']
                return {'provider':'OpenAI','findings':{'executive_summary':{'text':mode,'event_ids':[packet['events'][0]['id']]}},
                        'generated':int(time()),'usage':{}}
            mock.setattr(enterprise,'generate',mock_generate)
            assert soc.post(path+'/ai-report',json={'mode':'full'}).json()['generated']
            assert soc.post(path+'/ai-report',json={'mode':'quick'}).json()['generated']
            saved=soc.get(path+'/ai-evidence').json()['saved']
            assert saved['report']['findings']['executive_summary']['text']=='full'
        calls = []

        def monitored_generate(org, packet, mode):
            calls.append([row['id'] for row in packet['events']])
            return mock_generate(org, packet, mode)

        def process_due(expected=True):
            with enterprise.engine.begin() as conn:
                run(conn, 'UPDATE ai_investigation_sessions SET next_check=0 WHERE incident_id=:id', id=incident)
            assert monitor.process_next(enterprise.engine, enterprise.investigation, enterprise.audit) is expected

        with monkeypatch.context() as mock:
            mock.setattr(monitor, 'generate', monitored_generate)
            process_due()
            assert latest.json()['id'] in calls[-1]
            assert soc.get(path+'/ai-evidence').json()['monitor']['state'] == 'updated'
            assert soc.post(events_route,json={**extra,'external_id':identifier(),'asset':'unrelated'},headers=header).status_code == 202
            process_due()
            assert len(calls) == 1
            related = soc.post(events_route,json={**extra,'external_id':identifier(),'kind':'auth_anomaly'},headers=header)
            assert related.status_code == 202 and related.json()['alert_id']
            process_due()
            assert related.json()['id'] in calls[-1]
            context = soc.get(path+'/ai-evidence').json()
            revision_path = path+'/ai-revisions/'+context['current_revision']
            saved_revision = soc.get(revision_path).json()
            assert related.json()['id'] in {event['id'] for event in saved_revision['evidence']['events']}
            assert other.get(revision_path).status_code == 404
            assert len(context['revisions']) == 4

            def provider_failed(*_args):
                raise enterprise.ProviderError('Test provider timeout')

            mock.setattr(monitor, 'generate', provider_failed)
            assert soc.post(events_route,json={**extra,'external_id':identifier()},headers=header).status_code == 202
            process_due()
            context = soc.get(path+'/ai-evidence').json()
            assert context['monitor']['state'] == 'failed'
            assert context['saved'] == saved_revision
            assert len(context['revisions']) == 4
            assert soc.post(path+'/ai-monitor', json={'active': False}).status_code == 200
            process_due(False)
            assert soc.post(path+'/ai-monitor', json={'active': True}).status_code == 200
            assert soc.get(path+'/ai-evidence').json()['monitor']['state'] == 'starting'
        assert other.post(path+'/notes', json={'body':'Unauthorized note'}).status_code == 404
        investigation = soc.get(path).json()
        assert len(investigation['evidence']) == 5
        assert 'T1110' in investigation['technique']
        assert investigation['method'] == 'Evidence rules'
        assert soc.post(path+'/ai-summary',json={}).json() == {'generated':False}
        assert soc.post(path+'/assign',json={'user_id':other.get('/api/me').json()['id']}).status_code == 404
        assignee=soc.get('/api/me').json()['id']
        assert soc.post(path+'/assign',json={'user_id':assignee}).status_code == 200
        assert soc.get(path).json()['assigned_to'] == assignee
        assert soc.post(path+'/notes', json={'body':'Reviewed the five evidence records'}).status_code == 200

        for action, result, restricted in [('restrict_test_account','restricted',True),
                                            ('restore_test_account','restored',False)]:
            requested = soc.post(path+'/responses/'+action, json={})
            assert requested.status_code == 201, requested.text
            action_id = requested.json()['id']
            assert lab.post('/lab/sync', json={}).json()['confirmed'] == []
            assert other.post('/api/responses/'+action_id+'/approve', json={}).status_code == 409
            assert soc.post('/api/responses/'+action_id+'/reject', json={}).status_code == 200
            assert lab.post('/lab/sync', json={}).json()['confirmed'] == []
            assert soc.post(path+'/responses/'+action, json={}).json()['id'] == action_id
            assert soc.post('/api/responses/'+action_id+'/approve', json={}).status_code == 200
            sync = lab.post('/lab/sync', json={})
            assert sync.status_code == 200, sync.text
            assert sync.json()['confirmed'] == [result]
            assert lab.get('/lab/status').json()['restricted'] is restricted
            assert lab.get('/lab/sample-portal').status_code == (423 if restricted else 200)
            assert any(row['id']==action_id and row['result']==result for row in soc.get('/api/responses').json())
            if restricted:
                assert soc.post(path+'/close',json={'body':'Attempt before restoration'}).status_code==409

        assert soc.post(path+'/close', json={'body':'Lab account restored and verified'}).status_code == 200
        assert soc.get(path).json()['status'] == 'closed'
        assert 'response.restored' in {row['action'] for row in soc.get('/api/audit').json()}
        assert soc.post('/api/logout',json={}).status_code == 200
        assert soc.get('/api/me').status_code == 401
        assert soc.post('/api/login',json={'email':'test1@example.test','password':PASSWORD}).json()['onboarded']

    enterprise.engine.dispose()
    demo.engine.dispose()
    # Fresh application lifecycle rereads records from independent files.
    with TestClient(enterprise.app) as restarted, TestClient(demo.app) as restarted_lab:
        assert restarted.post('/api/login',json={'email':'test1@example.test','password':PASSWORD}).status_code == 200
        assert restarted.get(path).json()['resolution'] == 'Lab account restored and verified'
        assert restarted_lab.post('/lab/login',json={'password':PASSWORD}).status_code == 200
        assert not restarted_lab.get('/lab/status').json()['restricted']

def test_invitations_recovery_and_removed_intelligence_route(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINELX_DATABASE_URL','sqlite:///'+(tmp_path/'accounts.sqlite3').as_posix())
    monkeypatch.setattr(enterprise,'engine',engine_for('SENTINELX_DATABASE_URL','unused'))
    with TestClient(enterprise.app) as admin, TestClient(enterprise.app) as viewer:
        assert admin.post('/api/register',json={'organization':'Example','name':'Example Admin','email':'admin@example.test',
                                                'password':PASSWORD,'confirm':PASSWORD}).status_code==201
        invite=admin.post('/api/invitations',json={'email':'viewer@example.test','role':'viewer'}).json()['token']
        join={'email':'viewer@example.test','role':'admin','name':'Example Viewer','password':PASSWORD,'token':invite}
        assert viewer.post('/api/accept-invitation',json=join).status_code==201
        assert viewer.get('/api/me').json()['role']=='viewer'
        assert viewer.post('/api/accept-invitation',json=join).status_code==422
        assert viewer.post('/api/invitations',json={'email':'x@example.test','role':'analyst'}).status_code==403
        assert viewer.post('/api/integrations',json={'kind':'DemoLab','name':'Demo'}).status_code==403
        assert admin.post('/api/intelligence',json={'indicator':'example.test'}).status_code==404
        code=viewer.post('/api/recovery-code',json={}).json()['token']
        replacement={'token':code,'password':'new-local-password'}
        assert viewer.post('/api/reset-password',json=replacement).status_code==200
        assert viewer.get('/api/me').status_code==401
        assert viewer.post('/api/reset-password',json=replacement).status_code==422
        assert viewer.post('/api/login',json={'email':join['email'],'password':PASSWORD}).status_code==401
        assert viewer.post('/api/login',json={'email':join['email'],'password':replacement['password']}).status_code==200
    enterprise.engine.dispose()

