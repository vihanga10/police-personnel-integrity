import json
import urllib.request
from research_workspace_https_fixture import server
from scoped_access_http_fixture import request
from research_workspace_fixture import PASSWORD,identifier,review_body,disclosure,sign,presentation
from scoped_access_fixture import grant

def test_real_https_headers_workflow_expiry_revocation_and_recovery(tmp_path):
    with server(tmp_path) as (store,key,origin,context,cert):
        def call(path,**kw):return request(origin,context,path,**kw)
        with urllib.request.urlopen(origin+'/',context=context) as response:
            html=response.read().decode();headers=dict(response.headers)
        assert 'Finding reviews' in html and "script-src 'self'" in headers['content-security-policy']
        assert "'unsafe-inline'" not in headers['content-security-policy'] and headers['cache-control']=='no-store'
        for asset in ('app.js','styles.css'):
            with urllib.request.urlopen(origin+'/assets/'+asset,context=context) as r:assert r.status==200
        assert call('/api/research/officers/'+identifier(1))[0]==401
        status,h,b=call('/api/auth/login',method='POST',body={'username':'station.one','password':PASSWORD})
        assert status==200 and all(v in h['set-cookie'] for v in ('HttpOnly','Secure','SameSite=strict'))
        cookie=h['set-cookie'].split(';')[0];csrf=b['csrf_token']
        def auth(path,**kw):return call(path,cookie=cookie,csrf=csrf,**kw)
        assert auth('/api/officers/search',method='POST',body={'kind':'NAME','query':'විහඟ'})[2]['total']==1
        assert auth('/api/research/officers/'+identifier(5))[0]==404
        assert auth('/api/research/officers/'+identifier(1))[2]['fresh_live_verification'] is False
        b=review_body();a=auth('/api/research/requests',method='POST',body=b)
        assert a[0]==200 and a[2]['status']=='PENDING_AUTHORITY'
        # Lost acknowledgement: request already committed; exact retry and GET
        # reconcile its original digest. No findings/chain runner is invoked.
        assert auth('/api/research/requests',method='POST',body=b)[2]==a[2]
        assert auth('/api/research/requests/'+b['operation_id'])[2]==a[2]
        assert auth('/api/research/requests',method='POST',body=b,extra_headers={'Origin':'https://evil.invalid'})[0]==403
        assert auth('/api/research/history?nic=private',method='POST',body={})[0]==400
        d=disclosure(key,now=store.clock()+2,assignment='UNRESOLVED');d['payload']['issued_at']=int(store.clock())
        store.import_grant(sign(key,d['payload']))
        assert auth('/api/research/officers/'+identifier(1))[0]==403
        assert auth('/api/officers/'+identifier(1))[0]==200
        store.access.put_account(grant(key,version=2,active=False))
        assert auth('/api/research/officers/'+identifier(1))[0] in (401,403)

def test_real_process_restart_invalidates_cookie_but_preserves_request(tmp_path):
    with server(tmp_path) as (store,key,origin,context,cert):
        status,h,b=request(origin,context,'/api/auth/login',method='POST',body={'username':'station.one','password':PASSWORD})
        cookie=h['set-cookie'].split(';')[0];csrf=b['csrf_token'];body=review_body()
        original=request(origin,context,'/api/research/requests',method='POST',body=body,cookie=cookie,csrf=csrf)[2]
    config=tmp_path/'workspace-config.json'
    with server(tmp_path,prepared=(store,key,config)) as (_,_,origin,context,_):
        assert request(origin,context,'/api/auth/session',cookie=cookie)[0]==401
        _,h,b=request(origin,context,'/api/auth/login',method='POST',body={'username':'station.one','password':PASSWORD})
        newcookie=h['set-cookie'].split(';')[0]
        status,_,recovered=request(origin,context,'/api/research/requests/'+body['operation_id'],cookie=newcookie)
        assert status==200 and recovered==original and recovered['chain_submitted'] is False
        status,_,recent=request(origin,context,'/api/research/officers/'+identifier(1)+'/requests',cookie=newcookie)
        assert status==200 and recent['items']==[original]
