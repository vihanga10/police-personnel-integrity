"""Explicit private provisioning and bounded mTLS witness transport.

Internal service integration, not a public personnel API or deployment command.
Production independent administration, restore controls and key lifecycle remain
operational requirements. Keys and certificates are supplied, never generated.
"""
from copy import deepcopy
from hashlib import sha256
from http import client as http
from http.server import BaseHTTPRequestHandler,HTTPServer
from socketserver import ThreadingMixIn
from pathlib import Path
from urllib.parse import urlsplit
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID as EKU
from app.identity import observed_recording_journal as J
from app.identity import recording_tip_witness as W
from app.identity.historical_reconstruction import require

POLICY='PRIVATE_WITNESS_MTLS_PROVISIONING_V1'
PATH='/v1/recording-tip-witness/exchange'
MAX_BODY=16384
MAX_HEADERS=8192
FIELDS=W.SCOPE|{'policy','kind','enrollment_sha256','endpoint','ca_sha256','server_certificate_sha256',
    'clients','writer_keys_sha256','witness_keys_sha256','created_at','expires_at','limits'}


class WitnessTransportError(ConnectionError):pass


def _private(path,repo):
    path=Path(path).expanduser().absolute();J._private_root(path.parent,repo)
    require(not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
        path.stat().st_mode&0o077==0,'Private controlled transport file required.')
    return path


def _json(data):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'Duplicate JSON key refused.');result[key]=value
        return result
    def invalid(value):raise ValueError('Non-finite JSON refused.')
    value=json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_constant=invalid)
    require(type(value) is dict,'Witness JSON object required.');return value


def _endpoint(value):
    require(type(value) is str and len(value)<=2048 and all(32<ord(c)<127 for c in value),
        'Explicit ASCII witness endpoint required.')
    parsed=urlsplit(value)
    require(parsed.scheme=='https' and parsed.hostname and parsed.username is None and
        parsed.password is None and not parsed.query and not parsed.fragment and parsed.path==PATH,
        'Pinned HTTPS witness endpoint required.')
    require(1<=(443 if parsed.port is None else parsed.port)<=65535,'Witness endpoint port differs.')
    return parsed


def _limits(timeout=5,max_connections=8,requests_per_minute=60):
    require(type(timeout) in (int,float) and 0.1<=timeout<=10 and
        type(max_connections) is int and 1<=max_connections<=16 and
        type(requests_per_minute) is int and 1<=requests_per_minute<=120,'Bounded witness limits required.')
    return dict(max_body_bytes=MAX_BODY,request_timeout_seconds=timeout,
        max_connections=max_connections,requests_per_minute=requests_per_minute)


def _certificate(path,repo):
    data=_private(path,repo).read_bytes()
    require(data.count(b'-----BEGIN CERTIFICATE-----')==1,'Single directly issued certificate required.')
    cert=x509.load_pem_x509_certificate(data)
    require(cert.not_valid_before_utc<=J._now()<cert.not_valid_after_utc,'Transport certificate expired or future.')
    return cert


def _fingerprint(cert):return sha256(cert.public_bytes(S.Encoding.DER)).hexdigest()


def _public(key):return key.public_bytes(S.Encoding.DER,S.PublicFormat.SubjectPublicKeyInfo)


def _ca(path,repo):
    cert=_certificate(path,repo)
    require(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca and
        cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign,'Private issuing CA required.')
    cert.verify_directly_issued_by(cert);return cert


def _leaf(path,repo,ca,purpose):
    cert=_certificate(path,repo);cert.verify_directly_issued_by(ca)
    require(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca and
        purpose in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
        'Transport certificate purpose differs.')
    return cert


def _key(cert,path,repo,password):
    private=S.load_pem_private_key(_private(path,repo).read_bytes(),password=password)
    require(_public(private.public_key())==_public(cert.public_key()),'TLS certificate/key mismatch.')


def _hostname(cert,host):
    names=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:address=ipaddress.ip_address(host)
    except ValueError:
        require(host.lower() in [name.lower() for name in names.get_values_for_type(x509.DNSName)],
            'Exact endpoint DNS SAN required; wildcard/CN fallback refused.')
    else:require(address in names.get_values_for_type(x509.IPAddress),'Endpoint IP SAN differs.')


def _publish_profile(path,receipt,check):
    data=(J.canonical(receipt)+'\n').encode();temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.witness-profile-',delete=False) as stream:
            temporary=Path(stream.name);os.fchmod(stream.fileno(),0o600)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        check();os.link(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temporary is not None:temporary.unlink(missing_ok=True)
    return sha256(data).hexdigest()


def provision(service,*,profile_path,endpoint,ca_certificate,server_certificate,server_key,
        client_certificates,server_key_password=None,timeout=5,max_connections=8,requests_per_minute=60):
    """Offline trusted operator action: validate then append a signed public profile.

    Requires an already enrolled witness and externally retained enrollment pin.
    This does not enroll/reset a store, bind a socket, deploy or change a key.
    Certificate map: pinned registry writer key ID -> client certificate path.
    """
    parsed=_endpoint(endpoint);limits=_limits(timeout,max_connections,requests_per_minute)
    target=Path(profile_path).expanduser().absolute();root=J._private_root(target.parent,service.repo)
    require(not root.is_relative_to(service.root) and not service.root.is_relative_to(root),
        'Provisioning profile storage must be separate from witness ledger.')
    require(not target.exists() and not target.is_symlink(),'Provisioning never overwrites a profile.')
    ca=_ca(ca_certificate,service.repo);server=_leaf(server_certificate,service.repo,ca,EKU.SERVER_AUTH)
    _key(server,server_key,service.repo,server_key_password);_hostname(server,parsed.hostname)
    require(type(client_certificates) is dict and set(client_certificates)==set(service.writer_keys),
        'Every pinned writer needs exactly one controlled client certificate.')
    certificates=[ca,server];clients={}
    for key_id,path in client_certificates.items():
        cert=_leaf(path,service.repo,ca,EKU.CLIENT_AUTH);certificates.append(cert)
        fingerprint=_fingerprint(cert);require(fingerprint not in clients,'Duplicate client certificate refused.')
        clients[fingerprint]=key_id
    publics=[_public(cert.public_key()) for cert in certificates]
    signing={_public(Ed25519PublicKey.from_public_bytes(value)) for keys in
        (service.writer_keys,service.witness_keys) for value in keys.values()}
    require(len(set(publics))==len(publics) and not set(publics)&signing,
        'CA, endpoint, client and application signing keys must be separate.')
    context=_context(True);context.load_verify_locations(cafile=str(_private(ca_certificate,service.repo)))
    context.load_cert_chain(str(_private(server_certificate,service.repo)),str(_private(server_key,service.repo)),password=server_key_password)
    with service._locked():
        history=service._history()
        value=dict(policy=POLICY,kind='PROVISIONING',**service.scope,enrollment_sha256=service.expected_enrollment,
            endpoint=endpoint,ca_sha256=_fingerprint(ca),server_certificate_sha256=_fingerprint(server),clients=clients,
            writer_keys_sha256=W._key_digest(service.writer_keys),witness_keys_sha256=W._key_digest(service.witness_keys),
            created_at=J._now().isoformat(),expires_at=min(cert.not_valid_after_utc for cert in certificates).isoformat(),limits=limits)
        receipt=J._sign(value,service.signer,service.key_id,POLICY)
        def check():
            require(service._history()==history,'Witness changed during provisioning.')
            _profile_value(receipt,service.witness_keys)
        return _publish_profile(target,receipt,check)


def _profile_value(receipt,keys):
    value=J._verify(receipt,keys,FIELDS,'PROVISIONING',POLICY)
    W._scope(value['witness_id'],value['registry_id'],value['journal_anchor']);_endpoint(value['endpoint'])
    for field in ('enrollment_sha256','ca_sha256','server_certificate_sha256','writer_keys_sha256','witness_keys_sha256'):J._hash(value[field])
    require(value['witness_keys_sha256']==W._key_digest(keys),'Provisioning witness key inventory differs.')
    require(J._time(value['created_at'])<=J._now()<J._time(value['expires_at']),'Provisioning profile expired or future.')
    require(type(value['clients']) is dict and bool(value['clients']),'Pinned TLS clients required.')
    for fingerprint,key_id in value['clients'].items():J._hash(fingerprint);J._text(key_id)
    limits=value['limits']
    require(type(limits) is dict and set(limits)=={'max_body_bytes','request_timeout_seconds','max_connections','requests_per_minute'},
        'Provisioning limit inventory differs.')
    require(limits==_limits(limits['request_timeout_seconds'],limits['max_connections'],limits['requests_per_minute']),
        'Provisioning limits differ.')
    return value


def load_profile(path,expected_sha256,keys,repo):
    J._hash(expected_sha256);data=_private(path,repo).read_bytes()
    require(len(data)<=MAX_BODY and sha256(data).hexdigest()==expected_sha256,'Provisioning profile file pin differs.')
    return deepcopy(_profile_value(_json(data),keys))


def _context(server=False):
    require(ssl.HAS_TLSv1_3,'TLS 1.3 support required.')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version=ssl.TLSVersion.TLSv1_3;context.verify_mode=ssl.CERT_REQUIRED
    if not server:context.check_hostname=True;context.hostname_checks_common_name=False
    context.options|=ssl.OP_NO_COMPRESSION;return context


def _abort(connection):
    try:connection.shutdown(socket.SHUT_RDWR)
    except OSError:pass


def _length(headers):
    values=headers.get_all('Content-Length',[])
    require(len(values)==1 and values[0].isascii() and values[0].isdigit() and
        0<int(values[0])<=MAX_BODY and not headers.get_all('Transfer-Encoding') and
        not headers.get_all('Content-Encoding'),'Bounded unambiguous body framing required.')
    return int(values[0])


class HTTPSWitnessTransport:
    """Pinned direct HTTPS callable for WitnessClient; never follows redirects."""
    def __init__(self,*,profile_path,expected_profile_sha256,witness_keys,repo,ca_certificate,
            client_certificate,client_key,client_key_password=None):
        self.profile=load_profile(profile_path,expected_profile_sha256,witness_keys,repo)
        self.endpoint=_endpoint(self.profile['endpoint']);self.repo=repo
        ca=_ca(ca_certificate,repo);cert=_leaf(client_certificate,repo,ca,EKU.CLIENT_AUTH)
        _key(cert,client_key,repo,client_key_password)
        require(_fingerprint(ca)==self.profile['ca_sha256'] and _fingerprint(cert) in self.profile['clients'],
            'Transport CA/client certificate pins differ.')
        self.writer_key_id=self.profile['clients'][_fingerprint(cert)]
        context=_context();context.load_verify_locations(cafile=str(_private(ca_certificate,repo)))
        context.load_cert_chain(str(_private(client_certificate,repo)),str(_private(client_key,repo)),password=client_key_password)
        self.context=context

    def __call__(self,receipt):
        require(J._now()<J._time(self.profile['expires_at']),'Provisioning profile expired.')
        require(type(receipt) is dict and receipt.get('key_id')==self.writer_key_id,'Client certificate/writer binding differs.')
        body=J.canonical(deepcopy(receipt)).encode();require(len(body)<=MAX_BODY,'Witness request too large.')
        budget=self.profile['limits']['request_timeout_seconds'];deadline=time.monotonic()+budget
        connection=http.HTTPSConnection(self.endpoint.hostname,self.endpoint.port or 443,timeout=budget,context=self.context)
        connected=[None];response=None
        def abort():
            sock=connected[0] if connected[0] is not None else connection.sock
            if sock is not None:_abort(sock)
        timer=threading.Timer(budget,abort);timer.daemon=True;timer.start()
        try:
            connection.connect()
            connected[0]=connection.sock
            require(time.monotonic()<deadline,'Witness connection deadline exceeded.')
            require(sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()==self.profile['server_certificate_sha256'],
                'Pinned witness endpoint certificate differs.')
            connection.request('POST',PATH,body,headers={'Host':self.endpoint.netloc,'Content-Type':'application/json','Connection':'close'})
            response=connection.getresponse()
            require(response.status==200 and response.headers.get_all('Content-Type')==['application/json'],
                'Witness endpoint rejected the exchange.')
            length=_length(response.headers);data=response.read(length+1)
            require(len(data)==length and time.monotonic()<deadline,'Witness response incomplete or deadline exceeded.')
            return _json(data)
        except (OSError,http.HTTPException,ValueError,UnicodeError,RecursionError):
            raise WitnessTransportError('Witness HTTPS exchange failed; no acknowledgment accepted.') from None
        finally:
            timer.cancel()
            if response is not None:response.close()
            connection.close()


class _HeaderReader:
    def __init__(self,stream):self.stream=stream;self.total=0;self.headers=True
    def readline(self,limit=-1):
        if self.headers:limit=min(limit if limit>=0 else MAX_HEADERS+1,MAX_HEADERS-self.total+1)
        value=self.stream.readline(limit)
        if self.headers:
            self.total+=len(value)
            if self.total>MAX_HEADERS:raise http.LineTooLong('bounded witness headers')
        return value
    def __getattr__(self,name):return getattr(self.stream,name)


class _Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def setup(self):super().setup();self.rfile=_HeaderReader(self.rfile)
    def parse_request(self):
        result=super().parse_request();self.rfile.headers=False;return result
    def log_message(self,*args):pass
    def send_error(self,code,*args):self._send(code,{'status':'REJECTED'})
    def _send(self,status,payload):
        if time.monotonic()>=self.connection.witness_deadline:return
        data=J.canonical(payload).encode();self.send_response_only(status)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)))
        self.send_header('Connection','close');self.send_header('Cache-Control','no-store');self.end_headers()
        self.wfile.write(data);self.close_connection=True
    def handle_expect_100(self):self._send(417,{'status':'REJECTED'});return False
    def do_POST(self):
        self.close_connection=True
        if self.path!=PATH:self._send(404,{'status':'REJECTED'});return
        try:
            require(self.headers.get_all('Host')==[self.server.endpoint.netloc] and
                self.headers.get_all('Content-Type')==['application/json'] and
                not self.headers.get_all('Expect'),'Witness header inventory differs.')
            length=_length(self.headers);data=self.rfile.read(length)
            require(len(data)==length and time.monotonic()<self.connection.witness_deadline,'Incomplete witness request.')
            receipt=_json(data)
        except (ValueError,UnicodeError,RecursionError):self._send(400,{'status':'REJECTED'});return
        fingerprint=sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
        key_id=self.server.profile['clients'].get(fingerprint)
        if key_id is None or receipt.get('key_id')!=key_id:
            self._send(403,{'status':'REJECTED'});return
        if not self.server.allow(fingerprint):self._send(429,{'status':'REJECTED'});return
        try:
            require(J._now()<J._time(self.server.profile['expires_at']),'Profile expired.')
            response=self.server.service.exchange(receipt)
        except ValueError:self._send(409,{'status':'REJECTED'});return
        except Exception:self._send(503,{'status':'REJECTED'});return
        self._send(200,response)


class WitnessHTTPSServer(ThreadingMixIn,HTTPServer):
    """Explicitly bound, limited internal listener; instantiate only when authorized.

    No listener is created by installation/provisioning. Transport deadlines do
    not cancel already-committed witness operations or bound filesystem calls.
    """
    daemon_threads=True
    request_queue_size=16
    allow_reuse_address=True  # Allows controlled restart after TIME_WAIT, not SO_REUSEPORT.
    def __init__(self,bind_address,service,*,profile_path,expected_profile_sha256,ca_certificate,
            server_certificate,server_key,server_key_password=None):
        profile=load_profile(profile_path,expected_profile_sha256,service.witness_keys,service.repo)
        require(all(profile[key]==service.scope[key] for key in W.SCOPE) and
            profile['enrollment_sha256']==service.expected_enrollment and
            profile['writer_keys_sha256']==W._key_digest(service.writer_keys),'Listener witness binding differs.')
        endpoint=_endpoint(profile['endpoint'])
        require(type(bind_address) is tuple and len(bind_address)==2 and bind_address[1]==(endpoint.port or 443),
            'Listener port must match signed endpoint.')
        ca=_ca(ca_certificate,service.repo);cert=_leaf(server_certificate,service.repo,ca,EKU.SERVER_AUTH)
        _hostname(cert,endpoint.hostname);_key(cert,server_key,service.repo,server_key_password)
        require(_fingerprint(ca)==profile['ca_sha256'] and _fingerprint(cert)==profile['server_certificate_sha256'],
            'Listener certificate pins differ.')
        with service._locked():service._history()
        context=_context(True);context.load_verify_locations(cafile=str(_private(ca_certificate,service.repo)))
        context.load_cert_chain(str(_private(server_certificate,service.repo)),str(_private(server_key,service.repo)),password=server_key_password)
        self.service,self.profile,self.endpoint,self.context=service,profile,endpoint,context
        self.slots=threading.BoundedSemaphore(profile['limits']['max_connections'])
        self.rate_lock=threading.Lock();self.requests={}
        super().__init__(bind_address,_Handler)
    def allow(self,fingerprint):
        with self.rate_lock:
            now=time.monotonic();recent=[at for at in self.requests.get(fingerprint,[]) if now-at<60]
            self.requests[fingerprint]=recent
            if len(recent)>=self.profile['limits']['requests_per_minute']:return False
            recent.append(now);return True
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();self.shutdown_request(request);raise
    def process_request_thread(self,request,address):
        secured=None;timer=None;budget=self.profile['limits']['request_timeout_seconds']
        try:
            request.settimeout(budget);secured=self.context.wrap_socket(request,server_side=True)
            secured.witness_deadline=time.monotonic()+budget
            timer=threading.Timer(budget,_abort,args=(secured,));timer.daemon=True;timer.start()
            self.finish_request(secured,address)
        except Exception:pass  # No request bodies, key paths or exception detail in network/log output.
        finally:
            if timer is not None:timer.cancel()
            self.shutdown_request(secured if secured is not None else request);self.slots.release()
