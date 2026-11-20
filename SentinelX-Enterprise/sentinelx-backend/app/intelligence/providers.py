import base64
import ipaddress
import json
import os
import re
from urllib.parse import quote, urlsplit

import httpx

PROVIDERS = ('MISP', 'STIX/TAXII', 'VirusTotal')
PATTERN = re.compile(r"^\[\s*(ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|file:hashes\.'(?:MD5|SHA-1|SHA-256)')\s*=\s*'([^'\\]+)'\s*\]$")

def normalize(indicator):
    value = indicator.strip()
    try:
        address = ipaddress.ip_address(value)
        if '%' not in value:
            return f'ipv{address.version}-addr:value', str(address), 'ip_addresses'
    except ValueError:
        pass
    if re.fullmatch(r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', value):
        algorithm = {32:'MD5',40:'SHA-1',64:'SHA-256'}[len(value)]
        return f"file:hashes.'{algorithm}'", value.lower(), 'files'
    try:
        parsed = urlsplit(value)
        if parsed.scheme in ('https','http') and parsed.hostname and not parsed.username and not parsed.password:
            return 'url:value', value, 'urls'
    except ValueError:
        pass
    domain = value.rstrip('.').lower()
    if len(domain)<=253 and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}',domain):
        return 'domain-name:value', domain, 'domains'
    raise ValueError('Enter a valid IP address, domain, HTTP URL, or MD5/SHA-1/SHA-256 hash')

def read(client, method, url, **options):
    if urlsplit(url).scheme != 'https':
        raise ValueError('Provider requires HTTPS')
    with client.stream(method,url,**options) as response:
        if response.status_code == 404:
            return None
        response.raise_for_status()
        result = bytearray()
        for chunk in response.iter_bytes():
            result.extend(chunk)
            if len(result)>2_000_000:
                raise ValueError('Provider response is too large')
        return json.loads(result)

def virustotal(client, _kind, indicator, collection):
    key = os.getenv('SENTINELX_VT_API_KEY')
    if not key:
        return 'Not configured', None
    entry = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip('=') if collection=='urls' else indicator
    payload = read(client,'GET','https://www.virustotal.com/api/v3/'+collection+'/'+quote(entry,safe=''),
                   headers={'x-apikey':key})
    if payload is None:
        return 'No provider record', None
    stats = payload['data']['attributes']['last_analysis_stats']
    return f"{int(stats['malicious'])} malicious · {int(stats['suspicious'])} suspicious classifications", None

def misp(client, _kind, indicator, _collection):
    url,key = os.getenv('SENTINELX_MISP_URL'),os.getenv('SENTINELX_MISP_API_KEY')
    if not url or not key:
        return 'Not configured', None
    payload = read(client,'POST',url.rstrip('/')+'/attributes/restSearch',
                   headers={'Authorization':key,'Accept':'application/json'},
                   json={'value':indicator,'returnFormat':'json','published':True,'limit':100})
    if payload is None:
        return 'Provider endpoint unavailable', None
    attributes=payload['response']['Attribute']
    if any(attribute.get('value')==indicator for attribute in attributes):
        return 'Matching published attribute', None
    return 'No exact match in returned attributes', None

def taxii(client, kind, indicator, _collection):
    url = os.getenv('SENTINELX_TAXII_OBJECTS_URL')
    if not url:
        return 'Not configured', None
    headers={'Accept':'application/taxii+json;version=2.1'}
    token=os.getenv('SENTINELX_TAXII_TOKEN')
    if token:
        headers['Authorization']='Bearer '+token
    cursor=None
    for _page in range(3):
        params={'match[type]':'indicator','limit':100}
        if cursor:
            params['next']=cursor
        payload=read(client,'GET',url,headers=headers,params=params)
        if payload is None:
            return 'Provider endpoint unavailable', None
        for entry in payload.get('objects',[]):
            if entry.get('revoked') or entry.get('pattern_type')!='stix':
                continue
            match=PATTERN.fullmatch(entry.get('pattern',''))
            if match and match.groups()==(kind,indicator):
                confidence=entry.get('confidence')
                return 'Matching STIX indicator', confidence if type(confidence)==int and 0<=confidence<=100 else None
        if not payload.get('more'):
            return 'No supported exact match in collection', None
        cursor=payload.get('next')
        if not cursor:
            break
    return 'No match in the checked pages · partial search', None

def lookup(kind, indicator, collection):
    with httpx.Client(timeout=3,follow_redirects=False,trust_env=False) as client:
        for name, provider in zip(PROVIDERS,(misp,taxii,virustotal)):
            try:
                reputation, confidence = provider(client,kind,indicator,collection)
            except (httpx.HTTPError,ValueError,KeyError,TypeError,AttributeError):
                reputation,confidence='Provider unavailable',None
            yield {'source':name,'reputation':reputation,'confidence':confidence}

