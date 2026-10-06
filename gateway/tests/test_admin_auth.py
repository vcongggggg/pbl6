import pytest
from fastapi.testclient import TestClient
from app.core.config import get_settings

def test_admin_endpoints_require_auth(client: TestClient):
    endpoints = [
        ('/dashboard/reset-demo', None),
        ('/dashboard/seed-demo', None),
        ('/dashboard/toggle-waf-mode', None),
        ('/dashboard/simulate', {'attack_type': 'SQLI'}),
    ]
    
    # 1. Missing header -> 401
    for ep, payload in endpoints:
        res = client.post(ep, json=payload)
        assert res.status_code == 401, f'{ep} should return 401 when missing key'
        assert 'Unauthorized' in res.text

    # 2. Wrong key -> 401
    for ep, payload in endpoints:
        res = client.post(ep, json=payload, headers={'X-API-Key': 'wrong-key-value'})
        assert res.status_code == 401, f'{ep} should return 401 when wrong key'

    # 3. Valid key -> 200
    valid_headers = {'X-API-Key': get_settings().admin_api_key}
    for ep, payload in endpoints:
        res = client.post(ep, json=payload, headers=valid_headers)
        assert res.status_code == 200, f'{ep} should return 200 with valid key'
