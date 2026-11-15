from fastapi.testclient import TestClient
from app.graph_reader import GraphReader
from app.config import Settings, get_settings
from main import app, get_graph_reader, get_pin_store, get_policy_store

KEY = 'not-a-real-secret-but-more-than-32-character-long'

def settings():
    return Settings(tenant_id='tenant', graph_client_id='graph', graph_client_secret='secret',
        edge_app_sp_object_id='sp',cache_valid_hours=168,api_key=KEY,
        pin_table_endpoint='https://example.table.core.windows.net',pin_table_name='UserPinCredentials',
        pin_api_client_id='api',pin_api_tenant_id='tenant',edge_public_client_id='desktop',pin_cache_valid_hours=24)

class Graph:
    def list_direct_users(self, role_policies):
        return [{'entraObjectId':'U1','username':'test@example.test','displayName':'Test',
            'enabled':True,'roles':['Operator'],'permissions':['view_status'],
            'customSecurityAttributes': {'EdgeAccess':{'AllowedFunctions':['view_status']},
              'DeviceAccess': {'AllowedMachines':['Machine01']},
              'EmployeeDetails': {'Department':'Production'}}}]

class PolicyStore:
    def get_active_policies(self):
        return {'Operator': frozenset({'view_status'})}

class Store:
    def get_active_for_users(self, ids):
        return {}

def test_response_model_keeps_new_attributes():
    app.dependency_overrides[get_settings] = settings
    app.dependency_overrides[get_graph_reader] = Graph
    app.dependency_overrides[get_pin_store] = Store
    app.dependency_overrides[get_policy_store] = PolicyStore
    try:
        result = TestClient(app).get('/api/rbac/snapshot',headers={'x-functions-key':KEY})
        assert result.status_code == 200, result.text
        user = result.json()['users'][0]
        assert user['customSecurityAttributes']['EmployeeDetails']['Department'] == 'Production'
        assert user['customSecurityAttributes']['DeviceAccess']['AllowedMachines'] == ['Machine01']
        assert user['permissions'] == ['view_status']
    finally:
        app.dependency_overrides.clear()

def test_graph_reader_includes_attributes_without_granting_unknown_permissions(monkeypatch):
    reader = GraphReader(settings())
    monkeypatch.setattr(reader,'_access_token', lambda: 'dummy')
    role_id = '11111111-1111-1111-1111-111111111111'
    def fake_get(url, token, params=None):
        if '/users/' in url:
            return {'id':'U1','userPrincipalName':'test@example.test','displayName':'Test',
                'customSecurityAttributes': {
                    'EdgeAccess':{'AllowedFunctions':['view_status']},
                    'EmployeeDetails':{'Department':'Production'}}}
        return {'appRoles':[{'id':role_id,'value':'Operator','isEnabled':True,'allowedMemberTypes':['User']}]}
    monkeypatch.setattr(reader,'_get_json',fake_get)
    monkeypatch.setattr(reader,'_get_all_pages',lambda url, token: [
        {'principalType':'User','principalId':'U1','appRoleId':role_id}])
    result = reader.list_direct_users({"Operator": frozenset({"view_status"})})
    assert result[0]['customSecurityAttributes']['EmployeeDetails']['Department'] == 'Production'
    assert result[0]['permissions'] == ['view_status']
