from importlib import import_module

import httpx
import pytest

providers=import_module('sentinelx-backend.app.intelligence.providers')
ai=import_module('sentinelx-backend.app.investigations.provider')

@pytest.mark.parametrize(('value','collection'), [
    ('192.0.2.4','ip_addresses'),
    ('2001:db8::1','ip_addresses'),
    ('Example.TEST.','domains'),
    ('https://example.test/account','urls'),
    ('aa'*32,'files'),
])
def test_indicator_normalization(value,collection):
    assert providers.normalize(value)[2]==collection

def test_provider_parsers(monkeypatch):
    monkeypatch.setenv('SENTINELX_MISP_URL','https://misp.example.test')
    monkeypatch.setenv('SENTINELX_MISP_API_KEY','mock')
    monkeypatch.setenv('SENTINELX_TAXII_OBJECTS_URL','https://taxii.example.test/objects/')
    monkeypatch.setenv('SENTINELX_VT_API_KEY','mock')

    def handler(request):
        match request.url.host:
            case 'misp.example.test':
                assert request.method=='POST' and request.url.path=='/attributes/restSearch'
                return httpx.Response(200,json={'response':{'Attribute':[{'value':'example.test'}]}})
            case 'taxii.example.test':
                assert request.url.params['match[type]']=='indicator'
                return httpx.Response(200,json={'objects':[{'pattern_type':'stix','pattern':"[domain-name:value = 'example.test']",'confidence':75}]})
            case 'www.virustotal.com':
                assert request.url.path=='/api/v3/domains/example.test'
                return httpx.Response(200,json={'data':{'attributes':{'last_analysis_stats':{'malicious':2,'suspicious':1}}}})
        raise AssertionError(request.url)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        indicator=providers.normalize('example.test')
        assert providers.misp(client,*indicator)==('Matching published attribute',None)
        assert providers.taxii(client,*indicator)==('Matching STIX indicator',75)
        assert '2 malicious' in providers.virustotal(client,*indicator)[0]

def test_llm_draft_citation_scope(monkeypatch):
    monkeypatch.setenv('SENTINELX_LLM_GATEWAY_URL','https://model.example.test')
    facts=[{'id':'event-1','kind':'auth_failure','occurred':123,'simulated':1}]
    monkeypatch.setattr(ai,'read',lambda *_args,**_options:{'summary':'Observed failure','evidence_ids':['another-tenant']})
    assert ai.suggest(facts) is None
    monkeypatch.setattr(ai,'read',lambda *_args,**_options:{'summary':'Observed failure','evidence_ids':['event-1']})
    assert ai.suggest(facts)['evidence_ids']==['event-1']

