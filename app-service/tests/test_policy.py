import json
import pytest
from app.policy_repository import RolePolicyStore, PolicyStoreError
from app.permissions import effective_permissions, allowed_functions_from_profile

class Table:
    def __init__(self, rows): self.rows=rows
    def query_entities(self, query_filter):
        assert query_filter == "PartitionKey eq 'ROLE'"
        return iter(self.rows)

def repo(rows):
    store=object.__new__(RolePolicyStore)
    store.table=Table(rows)
    return store

def row(role, functions, enabled=True, version=1):
    return dict(PartitionKey='ROLE',RowKey=role,Enabled=enabled,
                PolicyVersion=version,AllowedFunctions=json.dumps(functions))

def test_roles_resolve_from_table_and_intersect_attributes():
    policies=repo([row('Operator',['view_status','start_operation']),
                   row('Supervisor',['view_status','change_settings'])]).get_active_policies()
    assert effective_permissions(['Operator'],['change_settings'], policies)==[]
    assert effective_permissions(['Supervisor'],['view_status','change_settings'],policies)==['change_settings','view_status']
    assert effective_permissions(['Unknown'],['view_status'],policies)==[]

def test_legacy_service_role_alias():
    policies=repo([row('ServiceEngineer',['service_tools'])]).get_active_policies()
    assert effective_permissions(['ServiceEnginner'],['service_tools'],policies)==['service_tools']

def test_new_function_can_be_added_without_code_edit():
    policies=repo([row('Operator',['inspect_temperature'])]).get_active_policies()
    profile={'customSecurityAttributes':{'EdgeAccess':{'AllowedFunctions':['inspect_temperature']}}}
    assert effective_permissions(['Operator'],allowed_functions_from_profile(profile),policies)==['inspect_temperature']

def test_disabled_policy_does_not_grant():
    policies=repo([row('Operator',['view_status'],enabled=False)]).get_active_policies()
    assert effective_permissions(['Operator'],['view_status'],policies)==[]

@pytest.mark.parametrize('rows', [[],[row('Operator','not-list')],
    [row('Operator',['View Status'])],[row('Operator',['view_status','view_status'])],
    [row('Operator',['view_status'],version=0)],
    [{'PartitionKey':'ROLE','RowKey':'Operator','AllowedFunctions':'[]','Enabled':'true','PolicyVersion':1}]])
def test_malformed_table_fails_closed(rows):
    with pytest.raises(PolicyStoreError): repo(rows).get_active_policies()

def test_storage_exception_fails_closed():
    class Broken:
        def query_entities(self, query_filter): raise OSError('down')
    store=object.__new__(RolePolicyStore); store.table=Broken()
    with pytest.raises(PolicyStoreError): store.get_active_policies()
