import pytest
from fastapi.testclient import TestClient
from app.config import Settings, get_settings
from main import app, get_graph_reader, get_pin_store, get_policy_store

KEY='not-a-real-secret-but-more-than-32-character-long'

def settings():
    return Settings(tenant_id='tenant',graph_client_id='graph',graph_client_secret='secret',
        edge_app_sp_object_id='sp',cache_valid_hours=168,api_key=KEY,
        pin_table_endpoint='https://example.table.core.windows.net',pin_table_name='UserPinCredentials',
        pin_api_client_id='api',pin_api_tenant_id='tenant',edge_public_client_id='desktop',pin_cache_valid_hours=24)

class Graph:
    def list_direct_users(self, role_policies):
        return [
            {'entraObjectId':'USER1','username':'operator@example.test','displayName':'Operator','enabled':True,'roles':['Operator'],'permissions':['view_status']},
            {'entraObjectId':'USER2','username':'engineer@example.test','displayName':'Engineer','enabled':True,'roles':['ServiceEnginner'],'permissions':['service_tools']},
            {'entraObjectId':'USER3','username':'disabled@example.test','displayName':'Disabled','enabled':False,'roles':[],'permissions':[]},
        ]
class Store:
    def get_active_for_users(self, ids):
        assert ids == ['USER1', 'USER2']
        return {'user1': {'algorithm':'scrypt-n16384-r8-p1-dk32','saltBase64':'salt','verifierBase64':'verifier','pinVersion':1}}
class PolicyStore:
    def get_active_policies(self):
        return {'Operator': frozenset({'view_status','start_operation'}), 'ServiceEngineer': frozenset({'service_tools'})}

class BrokenPolicyStore:
    def get_active_policies(self):
        raise RuntimeError('Storage outage')

class BrokenStore:
    def get_active_for_users(self, ids):
        raise RuntimeError('Azure outage')

@pytest.fixture(autouse=True)
def deps():
    app.dependency_overrides[get_settings]=settings
    app.dependency_overrides[get_graph_reader]=Graph
    app.dependency_overrides[get_pin_store]=Store
    app.dependency_overrides[get_policy_store]=PolicyStore
    yield
    app.dependency_overrides.clear()

def test_api_key_required():
    c=TestClient(app)
    assert c.get('/api/rbac/snapshot').status_code==401
    assert c.get('/api/rbac/snapshot',headers={'x-functions-key':'wrong'}).status_code==401
    assert c.get('/api/rbac/snapshot',headers={'Authorization':'Bearer fake'}).status_code==401

def test_full_snapshot_with_pin_and_no_device_id():
    r=TestClient(app).get('/api/rbac/snapshot',headers={'x-functions-key':KEY})
    assert r.status_code==200, r.text
    d=r.json()
    assert d['schemaVersion']==4
    assert 'deviceId' not in d
    assert len(d['users'])==3
    assert d['users'][0]['pinEnrolled'] is True
    assert d['users'][0]['pin']['verifierBase64']=='verifier'
    assert d['users'][1]['pinEnrolled'] is False and d['users'][1]['pin'] is None
    assert d['users'][2]['pin'] is None
    assert r.headers['Cache-Control'].startswith('no-store')
    assert d['pinValidUntilUtc'] != d['validUntilUtc']

def test_storage_failure_is_not_partial_success():
    app.dependency_overrides[get_pin_store]=BrokenStore
    r=TestClient(app).get('/api/rbac/snapshot',headers={'x-functions-key':KEY})
    assert r.status_code==503
    assert 'users' not in r.json()

def test_no_legacy_device_endpoint():
    assert TestClient(app).get('/api/device-access/anything',headers={'x-functions-key':KEY}).status_code==404

def test_enrollment_requires_entra():
    r=TestClient(app).post('/api/pin/enroll',headers={'x-functions-key':KEY},
        json={'pin':'12345678','confirmPin':'12345678'})
    # Test settings are syntactically illustrative; no JWT is parsed without bearer header.
    assert r.status_code==401

def test_policy_storage_failure_denies_bulk_snapshot():
    app.dependency_overrides[get_policy_store] = BrokenPolicyStore
    r = TestClient(app).get('/api/rbac/snapshot', headers={'x-functions-key': KEY})
    assert r.status_code == 503
    assert 'users' not in r.json()
