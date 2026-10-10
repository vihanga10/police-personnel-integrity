"""Ephemeral test certificates and actual loopback TLS; no production deployment."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from http import client as http
import ipaddress
import json
import socket
import ssl
import threading
import time
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization as S
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID as EKU
from app.identity import observed_recording_journal as J
from app.identity import recording_tip_witness as W
from app.identity import witness_secure_transport as T
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup,authorize,append,numbers
from test_protected_recording_review import verified,keys


def certs(root,clock):
    root.mkdir(mode=0o700);ca_key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Private TEST CA')])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(clock-timedelta(days=1))
        .not_valid_after(clock+timedelta(days=3)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
        .sign(ca_key,hashes.SHA256()))
    def write(label,cert,key):
        certificate=root/(label+'.pem');private=root/(label+'-key.pem')
        certificate.write_bytes(cert.public_bytes(S.Encoding.PEM));certificate.chmod(0o600)
        private.write_bytes(key.private_bytes(S.Encoding.PEM,S.PrivateFormat.PKCS8,S.NoEncryption()));private.chmod(0o600)
        return certificate,private
    ca_path,_=write('ca',ca,ca_key)
    def leaf(label,purpose,hostname='127.0.0.1',days=2,key=None):
        key=key or ec.generate_private_key(ec.SECP256R1())
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,label+' TEST ONLY')])
        addresses=[x509.IPAddress(ipaddress.ip_address(hostname))] if purpose==EKU.SERVER_AUTH else []
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(clock-timedelta(days=2))
            .not_valid_after(clock+timedelta(days=days)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
            .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
            .add_extension(x509.ExtendedKeyUsage([purpose]),False)
            .add_extension(x509.SubjectAlternativeName(addresses),False).sign(ca_key,hashes.SHA256()))
        return write(label,cert,key)
    server,server_key=leaf('server',EKU.SERVER_AUTH)
    client,client_key=leaf('client',EKU.CLIENT_AUTH)
    return dict(root=root,ca=ca_path,server=server,server_key=server_key,client=client,client_key=client_key,leaf=leaf)


@pytest.fixture
def secured(witnessed,tmp_path):
    t=witnessed;pki=certs(tmp_path/'test-pki',t['s']['clock'][0]);control=tmp_path/'control';control.mkdir(mode=0o700)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    endpoint=f'https://127.0.0.1:{port}'+T.PATH
    provision=dict(profile_path=control/'profile.json',endpoint=endpoint,ca_certificate=pki['ca'],
        server_certificate=pki['server'],server_key=pki['server_key'],client_certificates={'registry':pki['client']})
    pin=T.provision(t['server'],**provision)
    server_args=dict(profile_path=provision['profile_path'],expected_profile_sha256=pin,
        ca_certificate=pki['ca'],server_certificate=pki['server'],server_key=pki['server_key'])
    transport_args=dict(profile_path=provision['profile_path'],expected_profile_sha256=pin,
        witness_keys=t['args']['witness_keys'],repo=t['s']['repo'],ca_certificate=pki['ca'],
        client_certificate=pki['client'],client_key=pki['client_key'])
    return dict(t=t,pki=pki,provision=provision,pin=pin,port=port,server_args=server_args,transport_args=transport_args)


@contextmanager
def listener(d):
    server=T.WitnessHTTPSServer(('127.0.0.1',d['port']),d['t']['server'],**d['server_args'])
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.02},daemon=True);thread.start()
    try:yield server
    finally:server.shutdown();server.server_close();thread.join(timeout=2)


def wire_client(d):
    transport=T.HTTPSWitnessTransport(**d['transport_args'])
    return W.WitnessClient(**d['t']['client_args'],exchange=transport)


def request(d,**changes):
    t=d['t'];now=t['s']['clock'][0]
    value=dict(policy=W.REQUEST_POLICY,kind='REQUEST',**t['client'].scope,operation='HEAD',nonce='a'*64,
        expected_tip=None,proposed_tip=None,issued_at=now.isoformat(),expires_at=(now+timedelta(seconds=60)).isoformat())
    value.update(changes);return J._sign(value,t['r'].signer,t['r'].key_id,W.REQUEST_POLICY)


def raw_context(d,client=None,ca=None):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(ca or d['pki']['ca']))
    if client is not False:
        certificate,key=client or (d['pki']['client'],d['pki']['client_key'])
        context.load_cert_chain(str(certificate),str(key))
    return context


def raw_post(d,body=None,context=None,path=T.PATH,headers=None):
    connection=http.HTTPSConnection('127.0.0.1',d['port'],context=context or raw_context(d),timeout=1)
    body=J.canonical(request(d)).encode() if body is None else body
    try:
        connection.request('POST',path,body,headers={'Content-Type':'application/json',**(headers or {})})
        response=connection.getresponse();return response.status,response.read()
    finally:connection.close()


def test_real_mutual_tls_registration_restart_and_reported_query(secured):
    d=secured;t=d['t'];original={p:p.read_bytes() for root in (t['s']['root'],t['r'].root,t['server'].root) for p in root.iterdir()}
    with listener(d):
        client=wire_client(d);adapter=W.WitnessedCheckpointRegistry(t['r'],client)
        assert client.head()==t['tip'] and numbers(adapter.select()['state'],t['s']['clock'][0])==['fixture-100']
        t['s']['clock'][0]+=timedelta(seconds=1);new=append(t['s'],t['pin'],authorize(t['s'],t['pin']))
        latest=adapter.register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
        assert latest['sequence']==2 and numbers(adapter.select()['state'],t['s']['clock'][0])==['fixture-200']
    assert all(path.read_bytes()==data for path,data in original.items())
    restarted=W.DurableTipWitness(**t['args'],expected_enrollment=t['enrollment'])
    t['server']=restarted
    with listener(d):assert wire_client(d).head()==latest


def test_offline_provisioning_preserves_ledger_and_creates_no_listener_or_key(secured):
    d=secured;t=d['t'];path=d['provision']['profile_path']
    profile=T.load_profile(path,d['pin'],t['args']['witness_keys'],t['s']['repo'])
    assert profile['enrollment_sha256']==t['enrollment'] and path.stat().st_mode&0o777==0o600
    assert set(json.loads(path.read_text()))=={'key_id','payload','signature'}
    assert 'PRIVATE KEY' not in path.read_text() and str(d['pki']['server_key']) not in path.read_text()
    assert len(list(t['server'].root.iterdir()))==2
    with pytest.raises(ValueError,match='overwrites'):T.provision(t['server'],**d['provision'])


@pytest.mark.parametrize('kind',['plaintext','wrong_path','query','fragment','userinfo','whitespace','zero_port','bad_port'])
def test_endpoint_configuration_cannot_downgrade_or_redirect(secured,kind):
    d=secured;args=dict(d['provision']);args['profile_path']=args['profile_path'].parent/'refused.json'
    endpoint=args['endpoint']
    if kind=='plaintext':endpoint=endpoint.replace('https:','http:')
    elif kind=='wrong_path':endpoint=endpoint.replace(T.PATH,'/other')
    elif kind=='query':endpoint+='?redirect=other'
    elif kind=='fragment':endpoint+='#other'
    elif kind=='userinfo':endpoint=endpoint.replace('https://','https://user:password@')
    elif kind=='whitespace':endpoint=' '+endpoint
    elif kind=='zero_port':endpoint=endpoint.replace(':'+str(d['port']),':0')
    else:endpoint=endpoint.replace(':'+str(d['port']),':70000')
    args['endpoint']=endpoint
    with pytest.raises(ValueError):T.provision(d['t']['server'],**args)
    assert not args['profile_path'].exists()


@pytest.mark.parametrize('kind',['wrong_key','wrong_purpose','expired','wrong_san','missing_writer','public_keyfile','symlink','inside_ledger','no_enrollment','key_reuse','application_signing_reuse'])
def test_provisioning_preflight_rejects_invalid_material_without_writes(secured,kind):
    d=secured;t=d['t'];args=dict(d['provision']);args['profile_path']=args['profile_path'].parent/'refused.json'
    if kind=='wrong_key':args['server_key']=d['pki']['client_key']
    elif kind=='wrong_purpose':args['server_certificate']=d['pki']['client'];args['server_key']=d['pki']['client_key']
    elif kind=='expired':args['server_certificate'],args['server_key']=d['pki']['leaf']('expired',EKU.SERVER_AUTH,days=-1)
    elif kind=='wrong_san':args['server_certificate'],args['server_key']=d['pki']['leaf']('other-host',EKU.SERVER_AUTH,hostname='127.0.0.2')
    elif kind=='missing_writer':args['client_certificates']={}
    elif kind=='public_keyfile':d['pki']['server_key'].chmod(0o644)
    elif kind=='symlink':
        link=d['pki']['root']/'link-key';link.symlink_to(d['pki']['server_key']);args['server_key']=link
    elif kind=='inside_ledger':args['profile_path']=t['server'].root/'refused.json'
    elif kind=='no_enrollment':t['server'].expected_enrollment=None
    elif kind=='application_signing_reuse':
        args['server_certificate'],args['server_key']=d['pki']['leaf']('application-key',EKU.SERVER_AUTH,key=t['server'].signer)
    else:
        ca_key=S.load_pem_private_key((d['pki']['root']/'ca-key.pem').read_bytes(),password=None)
        args['server_certificate'],args['server_key']=d['pki']['leaf']('reused-key',EKU.SERVER_AUTH,key=ca_key)
    before={p:p.read_bytes() for p in t['server'].root.iterdir()}
    with pytest.raises(Exception):T.provision(t['server'],**args)
    assert not args['profile_path'].exists() and {p:p.read_bytes() for p in t['server'].root.iterdir()}==before


@pytest.mark.parametrize('kind',['wrong_pin','changed_profile','unknown_signer','public_profile','wrong_ca','wrong_client_key','unlisted_client'])
def test_client_startup_requires_pinned_profile_and_private_credentials(secured,kind):
    d=secured;args=dict(d['transport_args'])
    if kind=='wrong_pin':args['expected_profile_sha256']='f'*64
    elif kind=='changed_profile':d['provision']['profile_path'].write_text('{}')
    elif kind=='unknown_signer':args['witness_keys']={}
    elif kind=='public_profile':d['provision']['profile_path'].chmod(0o644)
    elif kind=='wrong_ca':args['ca_certificate']=certs(d['pki']['root'].parent/'other-pki',d['t']['s']['clock'][0])['ca']
    elif kind=='wrong_client_key':args['client_key']=d['pki']['server_key']
    else:args['client_certificate'],args['client_key']=d['pki']['leaf']('unlisted',EKU.CLIENT_AUTH)
    with pytest.raises(Exception):T.HTTPSWitnessTransport(**args)


@pytest.mark.parametrize('kind',['missing_client','untrusted_client','unlisted_client','wrong_hostname','untrusted_server_ca','tls_downgrade'])
def test_real_tls_rejects_unauthenticated_or_untrusted_peers(secured,kind):
    d=secured;before={p:p.read_bytes() for p in d['t']['server'].root.iterdir()}
    with listener(d):
        if kind=='missing_client':context=raw_context(d,client=False)
        elif kind=='untrusted_client':
            other=certs(d['pki']['root'].parent/'other-pki',d['t']['s']['clock'][0]);context=raw_context(d,client=(other['client'],other['client_key']))
        elif kind=='unlisted_client':context=raw_context(d,client=d['pki']['leaf']('unlisted',EKU.CLIENT_AUTH))
        elif kind=='untrusted_server_ca':
            other=certs(d['pki']['root'].parent/'other-pki',d['t']['s']['clock'][0]);context=raw_context(d,ca=other['ca'])
        elif kind=='tls_downgrade':
            context=raw_context(d);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.maximum_version=ssl.TLSVersion.TLSv1_2
        else:
            with socket.create_connection(('127.0.0.1',d['port']),timeout=1) as sock:
                with pytest.raises(ssl.SSLError):raw_context(d).wrap_socket(sock,server_hostname='wrong.invalid')
            assert {p:p.read_bytes() for p in d['t']['server'].root.iterdir()}==before;return
        if kind=='unlisted_client':assert raw_post(d,context=context)[0]==403
        else:
            with pytest.raises((OSError,http.HTTPException)):raw_post(d,context=context)
    assert {p:p.read_bytes() for p in d['t']['server'].root.iterdir()}==before


def test_same_ca_different_endpoint_certificate_is_rejected_before_request(secured):
    d=secured;alternate,key=d['pki']['leaf']('substituted-server',EKU.SERVER_AUTH);calls=[]
    original=d['t']['server'].exchange
    def exchange(receipt):calls.append(receipt);return original(receipt)
    d['t']['server'].exchange=exchange
    with listener(d) as server:
        server.context.load_cert_chain(str(alternate),str(key))
        with pytest.raises(T.WitnessTransportError):wire_client(d).head()
    assert not calls


@pytest.mark.parametrize('kind',['signer_binding','signature','scope','expired','duplicate_json','nan','path','content_type'])
def test_authenticated_connection_does_not_bypass_message_or_route_validation(secured,kind):
    d=secured;receipt=request(d);path=T.PATH;headers={}
    if kind=='signer_binding':receipt['key_id']='witness'
    elif kind=='signature':receipt['signature']='AAAA'
    elif kind=='scope':receipt=request(d,registry_id='wrong-registry')
    elif kind=='expired':
        now=d['t']['s']['clock'][0];receipt=request(d,issued_at=(now-timedelta(seconds=60)).isoformat(),expires_at=now.isoformat())
    elif kind=='path':path='/other'
    elif kind=='content_type':headers={'Content-Type':'text/plain'}
    body=J.canonical(receipt).encode()
    if kind=='duplicate_json':body=b'{"key_id":"registry","key_id":"registry"}'
    elif kind=='nan':body=b'{"key_id":"registry","payload":NaN}'
    before={p:p.read_bytes() for p in d['t']['server'].root.iterdir()}
    with listener(d):status,payload=raw_post(d,body=body,path=path,headers=headers)
    assert status in (400,403,404,409) and json.loads(payload)=={'status':'REJECTED'}
    assert {p:p.read_bytes() for p in d['t']['server'].root.iterdir()}==before


@pytest.mark.parametrize('kind',['duplicate_length','chunked','oversize','large_header','expect'])
def test_actual_http_framing_and_header_bounds(secured,kind):
    d=secured;headers=f'POST {T.PATH} HTTP/1.1\r\nHost: 127.0.0.1:{d["port"]}\r\nContent-Type: application/json\r\n'
    if kind=='duplicate_length':headers+='Content-Length: 2\r\nContent-Length: 2\r\n'
    elif kind=='chunked':headers+='Content-Length: 2\r\nTransfer-Encoding: chunked\r\n'
    elif kind=='oversize':headers+=f'Content-Length: {T.MAX_BODY+1}\r\n'
    elif kind=='large_header':headers+='X-Large: '+('a'*T.MAX_HEADERS)+'\r\nContent-Length: 2\r\n'
    else:headers+='Expect: 100-continue\r\nContent-Length: 2\r\n'
    with listener(d):
        sock=raw_context(d).wrap_socket(socket.create_connection(('127.0.0.1',d['port']),timeout=1),server_hostname='127.0.0.1')
        try:
            sock.sendall((headers+'\r\n{}').encode());response=http.HTTPResponse(sock);response.begin()
            assert response.status in (400,417,431) and json.loads(response.read())=={'status':'REJECTED'}
        finally:sock.close()


def test_rate_limit_is_per_pinned_client_and_does_not_change_ledger(secured):
    d=secured;args=dict(d['provision']);args['profile_path']=args['profile_path'].parent/'limited.json'
    pin=T.provision(d['t']['server'],**args,requests_per_minute=1)
    d['server_args'].update(profile_path=args['profile_path'],expected_profile_sha256=pin)
    d['transport_args'].update(profile_path=args['profile_path'],expected_profile_sha256=pin)
    with listener(d) as server:
        client=wire_client(d);assert client.head()==d['t']['tip']
        with pytest.raises(T.WitnessTransportError):client.head()
        for key in server.requests:server.requests[key]=[at-61 for at in server.requests[key]]
        assert client.head()==d['t']['tip']
    assert len(list(d['t']['server'].root.iterdir()))==2


@pytest.mark.parametrize('kind',['redirect','chunked','duplicate_json','oversize','truncated'])
def test_transport_rejects_untrusted_response_framing_without_following_redirects(secured,monkeypatch,kind):
    d=secured;calls=[]
    def respond(handler,status,payload):
        calls.append(status);body=J.canonical(payload).encode();length=len(body)
        if kind=='duplicate_json':body=b'{"payload":{},"payload":{}}';length=len(body)
        elif kind=='oversize':length=T.MAX_BODY+1
        elif kind=='truncated':length+=10
        handler.send_response_only(302 if kind=='redirect' else 200)
        handler.send_header('Content-Type','application/json');handler.send_header('Content-Length',str(length))
        if kind=='redirect':handler.send_header('Location','https://other.invalid'+T.PATH)
        elif kind=='chunked':handler.send_header('Transfer-Encoding','chunked')
        handler.send_header('Connection','close');handler.end_headers();handler.wfile.write(body);handler.close_connection=True
    monkeypatch.setattr(T._Handler,'_send',respond)
    with listener(d):
        with pytest.raises(T.WitnessTransportError):wire_client(d).head()
    assert len(calls)==1


def test_request_deadline_fails_without_a_cached_head_fallback(secured):
    d=secured;args=dict(d['provision']);args['profile_path']=args['profile_path'].parent/'short-timeout.json'
    pin=T.provision(d['t']['server'],**args,timeout=0.15)
    d['server_args'].update(profile_path=args['profile_path'],expected_profile_sha256=pin)
    d['transport_args'].update(profile_path=args['profile_path'],expected_profile_sha256=pin)
    original=d['t']['server'].exchange
    def slow(receipt):response=original(receipt);threading.Event().wait(0.3);return response
    d['t']['server'].exchange=slow
    with listener(d):
        start=time.monotonic()
        with pytest.raises(T.WitnessTransportError):wire_client(d).head()
        assert time.monotonic()-start<1.5
    assert len(list(d['t']['server'].root.iterdir()))==2


def test_service_io_error_is_sanitized_and_logs_no_request_contents(secured,capsys):
    d=secured
    def fail(receipt):raise OSError('TEST private key path and secret detail')
    d['t']['server'].exchange=fail
    with listener(d):status,body=raw_post(d)
    assert status==503 and body==b'{"status":"REJECTED"}'
    captured=capsys.readouterr();assert not captured.out and not captured.err


def test_profile_expiry_and_listener_scope_mismatch_fail_closed(secured):
    d=secured;transport=T.HTTPSWitnessTransport(**d['transport_args'])
    d['t']['s']['clock'][0]=J._time(transport.profile['expires_at'])
    with pytest.raises(ValueError,match='expired'):transport(request(d))
    with pytest.raises(ValueError):T.WitnessHTTPSServer(('127.0.0.1',d['port']),d['t']['server'],**d['server_args'])


def test_actual_https_response_loss_after_cas_recovers_durable_tip(secured,monkeypatch):
    d=secured;t=d['t'];original=T._Handler._send
    def drop(handler,status,payload):
        if status==200 and payload.get('payload',{}).get('operation')=='CAS':
            T._abort(handler.connection);handler.close_connection=True;return
        return original(handler,status,payload)
    monkeypatch.setattr(T._Handler,'_send',drop)
    t['s']['clock'][0]+=timedelta(seconds=1);new=append(t['s'],t['pin'],authorize(t['s'],t['pin']))
    with listener(d):
        adapter=W.WitnessedCheckpointRegistry(t['r'],wire_client(d))
        with pytest.raises(T.WitnessTransportError):adapter.register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
        assert wire_client(d).head()['sequence']==2
        assert numbers(adapter.select()['state'],t['s']['clock'][0])==['fixture-200']
    assert len(list(t['server'].root.iterdir()))==3


def test_bounded_connections_reject_extra_work_and_release_timed_out_slot(secured):
    d=secured;args=dict(d['provision']);args['profile_path']=args['profile_path'].parent/'one-connection.json'
    pin=T.provision(d['t']['server'],**args,timeout=0.25,max_connections=1)
    d['server_args'].update(profile_path=args['profile_path'],expected_profile_sha256=pin)
    d['transport_args'].update(profile_path=args['profile_path'],expected_profile_sha256=pin)
    with listener(d) as server:
        sock=raw_context(d).wrap_socket(socket.create_connection(('127.0.0.1',d['port']),timeout=1),server_hostname='127.0.0.1')
        try:
            # Occupy the only admitted worker with an incomplete authenticated body.
            sock.sendall((f'POST {T.PATH} HTTP/1.1\r\nHost: 127.0.0.1:{d["port"]}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n').encode())
            with pytest.raises(T.WitnessTransportError):wire_client(d).head()
            deadline=time.monotonic()+2
            while server.slots._value==0 and time.monotonic()<deadline:threading.Event().wait(0.02)
            assert server.slots._value==1 and wire_client(d).head()==d['t']['tip']
        finally:sock.close()


@pytest.mark.parametrize('method',['GET','PUT','DELETE'])
def test_listener_does_not_offer_files_or_other_service_routes(secured,method):
    d=secured
    with listener(d):
        connection=http.HTTPSConnection('127.0.0.1',d['port'],context=raw_context(d),timeout=1)
        try:
            connection.request(method,'/');response=connection.getresponse()
            assert response.status==501 and json.loads(response.read())=={'status':'REJECTED'}
        finally:connection.close()


@pytest.mark.parametrize('kind',['scope','enrollment','writers','port','server_certificate','server_key'])
def test_listener_startup_rejects_configuration_mismatch_before_binding(secured,kind):
    d=secured;service=d['t']['server'];args=dict(d['server_args']);port=d['port']
    if kind=='scope':service.scope=dict(service.scope,registry_id='wrong-registry')
    elif kind=='enrollment':service.expected_enrollment='f'*64
    elif kind=='writers':service.writer_keys=dict(service.writer_keys,extra=b'q'*32)
    elif kind=='port':port=port+1 if port<65535 else port-1
    elif kind=='server_certificate':
        args['server_certificate'],args['server_key']=d['pki']['leaf']('other-endpoint',EKU.SERVER_AUTH)
    else:args['server_key']=d['pki']['client_key']
    with pytest.raises(ValueError):T.WitnessHTTPSServer(('127.0.0.1',port),service,**args)
    with socket.socket() as probe:probe.bind(('127.0.0.1',port))


def test_encrypted_tls_private_keys_work_without_persisting_passwords(secured):
    d=secured;password=b'fixture-password-not-production'
    for path in (d['pki']['server_key'],d['pki']['client_key']):
        key=S.load_pem_private_key(path.read_bytes(),password=None)
        path.write_bytes(key.private_bytes(S.Encoding.PEM,S.PrivateFormat.PKCS8,S.BestAvailableEncryption(password)))
    args=dict(d['provision']);args['profile_path']=args['profile_path'].parent/'encrypted-key-profile.json'
    pin=T.provision(d['t']['server'],**args,server_key_password=password)
    assert password not in args['profile_path'].read_bytes()
    d['server_args'].update(profile_path=args['profile_path'],expected_profile_sha256=pin,server_key_password=password)
    d['transport_args'].update(profile_path=args['profile_path'],expected_profile_sha256=pin,client_key_password=password)
    with listener(d):assert wire_client(d).head()==d['t']['tip']
    wrong=dict(d['transport_args'],client_key_password=b'wrong-fixture-password')
    with pytest.raises(ValueError):T.HTTPSWitnessTransport(**wrong)
