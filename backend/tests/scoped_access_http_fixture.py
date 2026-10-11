"""Real TLS/socket fixture: actual ASGI application, private disposable access DB."""
import base64
from contextlib import contextmanager
from datetime import datetime,timedelta,timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes,serialization
from scoped_access_fixture import setup,PASSWORD,ROLE_SCOPES,grant,catalog,identifier,sign


def certificate(root):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'isolated-scope-test')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .sign(key,hashes.SHA256()))
    certfile=root/'server.crt';keyfile=root/'server.key'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    certfile.chmod(0o600);keyfile.chmod(0o600)
    return certfile,keyfile


@contextmanager
def server(root):
    root=Path(root).resolve();store,key,configfile=setup(root)
    for n,(role,level,scope) in enumerate(ROLE_SCOPES):
        g=grant(key,role,level,scope,login='user.'+str(n));g['payload']['user_id']=identifier(100+n)
        store.put_account(sign(key,g['payload']),PASSWORD)
    store.put_directory(catalog(key))
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    config=json.loads(configfile.read_text());origin='https://127.0.0.1:'+str(port);config['origin']=origin
    configfile.write_text(json.dumps(config));certfile,keyfile=certificate(root)
    backend=Path(__file__).resolve().parents[1]
    env={'PATH':os.environ.get('PATH',''),'PYTHONPATH':str(backend),
         'PPI_ACCESS_CONFIG':str(configfile),'PYTHONUNBUFFERED':'1'}
    log=root/'server.log';log.touch(mode=0o600)
    process=None
    try:
        with log.open('wb') as out:
            process=subprocess.Popen([sys.executable,'-m','uvicorn','app.access.api:application','--factory',
                '--host','127.0.0.1','--port',str(port),'--workers','1','--no-proxy-headers','--no-access-log',
                '--ssl-certfile',str(certfile),'--ssl-keyfile',str(keyfile),'--log-level','warning'],
                cwd=backend,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT)
        context=ssl.create_default_context(cafile=str(certfile));context.minimum_version=ssl.TLSVersion.TLSv1_3
        until=time.monotonic()+15
        while True:
            if process.poll() is not None:raise RuntimeError('Disposable ASGI server failed to start; inspect fixture log privately')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=1) as s:
                    with context.wrap_socket(s,server_hostname='127.0.0.1'):break
            except (OSError,ssl.SSLError):
                if time.monotonic()>=until:raise RuntimeError('Disposable HTTPS readiness timed out')
                time.sleep(.05)
        yield store,key,origin,context
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


def request(origin,context,path,*,method='GET',body=None,cookie=None,csrf=None,extra_headers=None):
    headers={'Origin':origin,'Content-Type':'application/json'}
    if cookie:headers['Cookie']=cookie
    if csrf:headers['X-CSRF-Token']=csrf
    headers.update(extra_headers or {})
    data=json.dumps(body,ensure_ascii=False).encode() if body is not None else None
    req=urllib.request.Request(origin+path,data=data,headers=headers,method=method)
    try:response=urllib.request.urlopen(req,context=context,timeout=15)
    except urllib.error.HTTPError as e:response=e
    with response:return response.status,dict(response.headers),json.loads(response.read())


def checks(root):
    completed=[]
    with server(root) as (store,key,origin,context):
        def call(path,**kwargs):return request(origin,context,path,**kwargs)
        assert call('/api/auth/session')[0]==401;completed.append('ANONYMOUS_DENIED')
        for n,expected in enumerate((6,6,4,3,2,2,1)):
            status,h,b=call('/api/auth/login',method='POST',body={'username':'user.'+str(n),'password':PASSWORD})
            assert status==200
            cookie=h['set-cookie'].split(';')[0];csrf=b['csrf_token']
            assert all(x in h['set-cookie'] for x in ('HttpOnly','Secure','SameSite=strict','Path=/'))
            assert call('/api/auth/session',cookie=cookie)[2]['role']==ROLE_SCOPES[n][0]
            status,h,b=call('/api/officers/search',method='POST',body={'kind':'NAME','query':'reported name'},cookie=cookie,csrf=csrf)
            assert status==200 and b['total']==expected
            status,h,b=call('/api/officers/search',method='POST',body={'kind':'NIC','query':'000000001V'},cookie=cookie,csrf=csrf)
            assert status==200 and b['total']==1
            assert call('/api/officers/'+identifier(1),cookie=cookie)[0]==200
            assert call('/api/officers/'+identifier(5 if n>=2 else 999),cookie=cookie)[0]==404
            completed.append('ROLE_'+ROLE_SCOPES[n][0])
        assert call('/api/officers/search',method='POST',body={'kind':'NAME','query':'reported'},cookie=cookie)[0]==403
        completed.append('CSRF_DENIED')
        assert call('/api/officers/search',method='POST',body={'kind':'NAME','query':'reported'},cookie=cookie,csrf=csrf,
                    extra_headers={'Origin':'https://attacker.invalid'})[0]==403
        completed.append('CROSS_ORIGIN_DENIED')
        assert call('/api/officers/search',method='POST',body={'kind':'NAME','query':'reported','role':'IGP'},cookie=cookie,csrf=csrf)[0]==400
        completed.append('REQUEST_SCOPE_FORGERY_DENIED')
        assert call('/api/officers/search?nic=not-a-real-value',method='POST',body={'kind':'NAME','query':'reported'},cookie=cookie,csrf=csrf)[0]==400
        completed.append('URL_SEARCH_REJECTED')
        assert call('/api/officers/search',method='POST',body={'kind':'NAME','query':'විහඟ'},cookie=cookie,csrf=csrf)[2]['total']==1
        completed.append('SINHALA_SEARCH_SCOPED')
        updated=grant(key,'STATION_OIC','STATION','S2',login='user.6',version=2)
        updated['payload']['user_id']=identifier(106);store.put_account(sign(key,updated['payload']))
        assert call('/api/auth/session',cookie=cookie)[0]==401;completed.append('LIVE_SCOPE_REVOCATION')
        status,h,b=call('/api/auth/login',method='POST',body={'username':'user.6','password':PASSWORD})
        assert status==200;cookie=h['set-cookie'].split(';')[0];csrf=b['csrf_token']
        assert call('/api/officers/'+identifier(1),cookie=cookie)[0]==404
        assert call('/api/officers/'+identifier(2),cookie=cookie)[0]==200
        completed.append('UPDATED_SCOPE_ENFORCED')
        assert call('/api/auth/logout',method='POST',body={},cookie=cookie,csrf=csrf)[0]==200
        assert call('/api/auth/session',cookie=cookie)[0]==401;completed.append('LOGOUT_REPLAY_DENIED')
    return completed
