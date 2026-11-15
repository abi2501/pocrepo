"""FastAPI v5 bulk snapshot import and offline authorization regression tests."""
from datetime import timedelta
import base64
import copy
import hashlib
import socket
import pytest

from app import db, rbac_client
from app.bulk_sync import import_bulk_snapshot
from app.security import verify_offline_secret
from app.actions import run_simulated_action
from app.util import utc_now
from app.cli import build_parser
from app.entra_auth import _scopes


def iso(t):
    return t.isoformat(timespec='seconds').replace('+00:00','Z')


def pin(value, version=1):
    salt=b'0123456789abcdef'
    h=hashlib.scrypt(value.encode(), salt=salt, n=16384,r=8,p=1,dklen=32)
    return {'algorithm':'scrypt-n16384-r8-p1-dk32', 'saltBase64':base64.b64encode(salt).decode(),
            'verifierBase64':base64.b64encode(h).decode(),'pinVersion':version}


def user(oid='test-operator', name='operator@example.invalid', p='123456', permissions=None):
    return {'entraObjectId':oid,'username':name,'displayName':'Test Operator','enabled':True,
            'roles':['Operator'], 'permissions':permissions or ['view_status','start_operation'],
            'pinEnrolled':p is not None,'pin':pin(p) if p is not None else None}


def snapshot(users=None, hours=10):
    now=utc_now()
    return {'schemaVersion':4,'version':int(now.timestamp()),'generatedUtc':iso(now),
            'validUntilUtc':iso(now+timedelta(hours=hours)),
            'pinValidUntilUtc':iso(now+timedelta(hours=min(hours, 8))),
            'source':{'assignmentMode':'direct-users-only'},
            'users':users if users is not None else [user(),user('test-supervisor','supervisor@example.invalid','654321',['view_status'])]}


def login(path, name='operator@example.invalid', pwd='123456'):
    return verify_offline_secret(path,name,pwd,5,120)


def test_all_users_and_pin_verifiers_imported(tmp_path):
    path=str(tmp_path/'cache.db')
    result=import_bulk_snapshot(path,snapshot())
    assert result['users']==2 and result['withPin']==2
    assert len(db.list_users(path))==2
    assert login(path)[0]
    assert login(path,'supervisor@example.invalid','654321')[0]
    assert not login(path,'supervisor@example.invalid','123456')[0]
    assert run_simulated_action(path,'operator@example.invalid','start_operation')[0]
    assert not run_simulated_action(path,'supervisor@example.invalid','start_operation')[0]


def test_unenrolled_user_cannot_login(tmp_path):
    path=str(tmp_path/'cache.db')
    import_bulk_snapshot(path,snapshot([user(p=None)]))
    assert not login(path)[0]


def test_removed_user_revoked_on_next_bulk_sync(tmp_path):
    path=str(tmp_path/'cache.db')
    snap=snapshot()
    import_bulk_snapshot(path,snap)
    newer=snapshot([user()]); newer['generatedUtc']=iso(utc_now()+timedelta(seconds=1))
    import_bulk_snapshot(path,newer)
    assert not login(path,'supervisor@example.invalid','654321')[0]
    assert db.get_offline_credential(path,'test-supervisor') is None


def test_cloud_pin_removal_deletes_local_verifier(tmp_path):
    path=str(tmp_path/'cache.db')
    import_bulk_snapshot(path,snapshot([user()]))
    import_bulk_snapshot(path,snapshot([user(p=None)]))
    assert not login(path)[0]


def test_malformed_pin_never_partially_updates_db(tmp_path):
    path=str(tmp_path/'cache.db')
    import_bulk_snapshot(path,snapshot())
    broken=snapshot([user(),user('test-supervisor','supervisor@example.invalid','654321')])
    broken['users'][1]['pin']['verifierBase64']='broken'
    with pytest.raises(ValueError,match='PIN verifier'):
        import_bulk_snapshot(path,broken)
    assert login(path)[0]
    assert login(path,'supervisor@example.invalid','654321')[0]


def test_reject_pin_version_rollback_and_atomicity(tmp_path):
    path=str(tmp_path/'cache.db')
    newer=snapshot([user()]); newer['users'][0]['pin']['pinVersion']=3
    import_bulk_snapshot(path,newer)
    with pytest.raises(ValueError,match='PIN version rollback'):
        import_bulk_snapshot(path,snapshot([user()]))
    assert login(path)[0]


def test_reject_snapshot_time_rollback(tmp_path):
    path=str(tmp_path/'cache.db')
    initial=snapshot([user()])
    import_bulk_snapshot(path,initial)
    old=copy.deepcopy(initial)
    old['generatedUtc']=iso(utc_now()-timedelta(hours=1))
    old['version']-=3600
    with pytest.raises(ValueError,match='rollback'):
        import_bulk_snapshot(path,old)


def test_pin_cache_expiration_blocks_offline(tmp_path):
    path=str(tmp_path/'cache.db')
    import_bulk_snapshot(path,snapshot([user()]))
    with db.connect(path) as conn:
        conn.execute('UPDATE offline_credentials SET credential_valid_until_utc=?',
                     (iso(utc_now()-timedelta(seconds=1)),))
        conn.commit()
    assert not login(path)[0]


def test_legacy_local_pin_not_accepted(tmp_path):
    path=str(tmp_path/'cache.db')
    import_bulk_snapshot(path,snapshot([user(p=None)]))
    verifier=pin('123456')
    db.save_offline_credential(path,'test-operator',verifier['algorithm'],
        verifier['saltBase64'],verifier['verifierBase64'])
    assert not login(path)[0]


def test_shared_key_auth_request(monkeypatch):
    calls=[]
    class Response:
        status_code=200
        def json(self):
            return {'schemaVersion':4,'users':[]}
    def fake_request(method, url, **kw):
        calls.append((method,url,kw));return Response()
    monkeypatch.setattr(rbac_client.requests,'request',fake_request)
    key='K'*40
    assert rbac_client.fetch_bulk_snapshot('https://example.com/api',key,10)['schemaVersion']==4
    _,url,kw=calls[0]
    assert url=='https://example.com/api/rbac/snapshot'
    assert kw['headers']['x-functions-key']==key
    assert 'Authorization' not in kw['headers']
    assert kw['allow_redirects'] is False
    with pytest.raises(rbac_client.CloudAPIError):
        rbac_client.fetch_bulk_snapshot('http://example.com/api',key,10)


def test_enrollment_uses_bearer_not_shared_key(monkeypatch):
    calls=[]
    class Response:
        status_code=201
        def json(self):
            return {'status':'enrolled'}
    def fake_request(method,url,**kw):
        calls.append((method,url,kw));return Response()
    monkeypatch.setattr(rbac_client.requests,'request',fake_request)
    rbac_client.enroll_pin('https://example.com/api','SECRET','123456',10)
    assert calls[0][1].endswith('/api/pin/enroll')
    assert calls[0][2]['headers']['Authorization']=='Bearer SECRET'
    assert 'x-functions-key' not in calls[0][2]['headers']
    assert _scopes('api-id')==['api://api-id/pin.enroll']


def test_cli_command_contract():
    p=build_parser()
    assert p.parse_args(['sync']).command=='sync'
    assert p.parse_args(['enroll','--flow','device']).command=='enroll'
    with pytest.raises(SystemExit):
        p.parse_args(['rbac-sync','--device-id','WIN-001'])


def test_offline_login_never_calls_network(tmp_path,monkeypatch):
    path=str(tmp_path/'cache.db')
    import_bulk_snapshot(path,snapshot([user()]))
    def fail(*a,**k):
        raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket,'create_connection',fail)
    assert login(path)[0]
