"""Durable witness service core and challenge-bound registry integration.

Internal backend interfaces, not a public endpoint. Independent deployment,
authenticated transport and protection of the witness against rollback remain
operational requirements. No production keys, RPC or research run is created.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
import base64
import fcntl
import os
import re
import secrets

from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from app.identity import observed_recording_journal as J
from app.identity import recording_checkpoint_registry as R
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest

POLICY='DURABLE_RECORDING_TIP_WITNESS_V1'
REQUEST_POLICY='RECORDING_TIP_WITNESS_REQUEST_V1'
RESPONSE_POLICY='RECORDING_TIP_WITNESS_RESPONSE_V1'
LIFETIME=timedelta(seconds=60)
SCOPE={'witness_id','registry_id','journal_anchor'}
REQUEST_FIELDS=SCOPE|{'policy','kind','operation','nonce','expected_tip','proposed_tip','issued_at','expires_at'}
RESPONSE_FIELDS=SCOPE|{'policy','kind','operation','nonce','request_sha256','tip','status','issued_at','expires_at'}
GENESIS_FIELDS=SCOPE|{'policy','kind','writer_keys_sha256','witness_keys_sha256','created_at'}
ENTRY_FIELDS=SCOPE|{'policy','kind','sequence','previous_entry_sha256','request','committed_at'}


def _key_digest(keys):
    return digest({key:base64.b64encode(value).decode() for key,value in keys.items()})


def _scope(witness_id,registry_id,journal_anchor):
    J._text(witness_id);J._text(registry_id);J._hash(journal_anchor)
    return dict(witness_id=witness_id,registry_id=registry_id,journal_anchor=journal_anchor)


def _request(receipt,keys,scope,at):
    value=J._verify(receipt,keys,REQUEST_FIELDS,'REQUEST',REQUEST_POLICY)
    require(all(value[key]==scope[key] for key in SCOPE),'Witness request scope differs.')
    J._hash(value['nonce']);R._pin(value['expected_tip']);R._pin(value['proposed_tip'])
    issued,expires=J._time(value['issued_at']),J._time(value['expires_at'])
    require(issued<=at<expires and expires==issued+LIFETIME,'Witness request expired or clock differs.')
    require(value['operation'] in {'HEAD','CAS'},'Witness request operation differs.')
    if value['operation']=='HEAD':
        require(value['expected_tip'] is None and value['proposed_tip'] is None,'HEAD cannot update witness state.')
    else:
        old,new=value['expected_tip'],value['proposed_tip']
        require(new is not None and new['sequence']==(old['sequence']+1 if old else 1),
            'Witness advancement must be exactly one registry entry.')
    return value


class DurableTipWitness:
    """Single enrolled journal, independently administered service-side store.

    Provision explicitly once, retain the enrollment hash in trusted service
    configuration, then reopen with that hash. Never re-enroll on missing files.
    This core provides no network listener or automatic deployment.
    """
    def __init__(self,*,root,repo,witness_id,registry_id,journal_anchor,crypto,backup,
            signer,key_id,witness_keys,writer_keys,expected_enrollment=None):
        self.root=J._private_root(root,repo);self.repo=repo
        self.scope=_scope(witness_id,registry_id,journal_anchor)
        self.crypto,self.backup=crypto,backup;self.signer,self.key_id=signer,key_id
        self.witness_keys,self.writer_keys=dict(witness_keys),dict(writer_keys)
        require(bool(self.writer_keys) and not set(witness_keys.values())&set(writer_keys.values()),
            'Witness authority and registry writer keys must be separate.')
        _key_digest(self.writer_keys);_key_digest(self.witness_keys)
        J._recorder(signer,key_id,self.witness_keys,crypto,backup)
        if expected_enrollment is not None:J._hash(expected_enrollment)
        self.expected_enrollment=expected_enrollment

    def _binding(self):
        return dict(artifact='DURABLE_RECORDING_TIP_WITNESS',policy=POLICY,**self.scope)

    @contextmanager
    def _locked(self):
        root=J._private_root(self.root,self.repo);fd=os.open(root,os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    def _files(self,staging=None):
        result={}
        for path in self.root.iterdir():
            if path==staging:continue
            require(path.name=='enrollment.encrypted.json' or
                re.fullmatch(r'advance-[0-9]{8}\.encrypted\.json',path.name),
                'Unknown witness artifact; preserve and investigate.')
            require(not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
                path.stat().st_mode&0o077==0,'Private witness artifact required.')
            result[path.name]=sha256(path.read_bytes()).hexdigest()
        return result

    def initialize(self):
        """Trusted one-time provisioning only; not a normal read/restart fallback."""
        with self._locked():
            require(self.expected_enrollment is None and not list(self.root.iterdir()),
                'Witness enrollment requires an explicitly new empty store.')
            value=dict(policy=POLICY,kind='ENROLLMENT',**self.scope,
                writer_keys_sha256=_key_digest(self.writer_keys),witness_keys_sha256=_key_digest(self.witness_keys),
                created_at=J._now().isoformat())
            def check(staging):require(not self._files(staging),'Witness changed during enrollment.')
            fingerprint=R._publish(self.root/'enrollment.encrypted.json',J._sign(value,self.signer,self.key_id,POLICY),
                self.crypto,self.backup,self._binding(),check)
            self.expected_enrollment=fingerprint
            return fingerprint

    def _history(self,staging=None):
        require(self.expected_enrollment is not None,'Trusted witness enrollment pin required.')
        files=self._files(staging)
        require(files.get('enrollment.encrypted.json')==self.expected_enrollment,
            'Witness enrollment missing or altered; never auto-initialize.')
        fingerprint,receipt=J._read(self.root/'enrollment.encrypted.json',self.crypto,self.backup,self._binding())
        base=J._verify(receipt,self.witness_keys,GENESIS_FIELDS,'ENROLLMENT',POLICY)
        require(all(base[key]==self.scope[key] for key in SCOPE) and
            base['writer_keys_sha256']==_key_digest(self.writer_keys) and
            base['witness_keys_sha256']==_key_digest(self.witness_keys),'Witness enrollment configuration differs.')
        last=J._time(base['created_at']);require(last<=J._now(),'Witness clock moved backwards.')
        names=sorted(name for name in files if name.startswith('advance-'))
        require(names==[f'advance-{index:08d}.encrypted.json' for index in range(1,len(names)+1)],
            'Witness advancement sequence gap.')
        tip=None;last_request=None;previous=fingerprint
        for index,name in enumerate(names,1):
            fingerprint,receipt=J._read(self.root/name,self.crypto,self.backup,self._binding())
            entry=J._verify(receipt,self.witness_keys,ENTRY_FIELDS,'ADVANCE',POLICY)
            require(all(entry[key]==self.scope[key] for key in SCOPE) and
                type(entry['sequence']) is int and entry['sequence']==index and
                entry['previous_entry_sha256']==previous,'Witness advancement chain differs.')
            committed=J._time(entry['committed_at'])
            require(last<=committed<=J._now(),'Witness commit clock differs.')
            request=_request(entry['request'],self.writer_keys,self.scope,committed)
            require(request['operation']=='CAS' and request['expected_tip']==tip,
                'Witness persisted compare-and-swap chain differs.')
            tip=deepcopy(request['proposed_tip']);last_request=request;previous=fingerprint;last=committed
        return dict(tip=tip,request=last_request,count=len(names),previous=previous,files=files,last=last)

    def _flush(self):
        fd=os.open(self.root,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def exchange(self,receipt):
        """Only a fresh signed request can read or compare-and-swap this scope."""
        receipt=deepcopy(receipt)
        with self._locked():
            request=_request(receipt,self.writer_keys,self.scope,J._now());history=self._history()
            if request['operation']=='CAS':
                if request['proposed_tip']==history['tip']:
                    require(history['request'] is not None and
                        request['expected_tip']==history['request']['expected_tip'],
                        'Witness idempotent retry differs from committed predecessor.')
                else:
                    require(request['expected_tip']==history['tip'],'Witness compare-and-swap conflict.')
                    now=J._now();require(now>=history['last'],'Witness clock moved backwards.')
                    value=dict(policy=POLICY,kind='ADVANCE',**self.scope,sequence=history['count']+1,
                        previous_entry_sha256=history['previous'],request=receipt,committed_at=now.isoformat())
                    def check(staging):
                        _request(receipt,self.writer_keys,self.scope,J._now())
                        require(self._history(staging)==history,'Witness changed before publication.')
                    R._publish(self.root/f"advance-{history['count']+1:08d}.encrypted.json",
                        J._sign(value,self.signer,self.key_id,POLICY),self.crypto,self.backup,self._binding(),check)
                    history=self._history()
            # Also establishes directory durability after a previous link/flush interruption.
            self._flush();_request(receipt,self.writer_keys,self.scope,J._now())
            require(self._history()==history,'Witness changed before response.')
            now=J._now()
            response=dict(policy=RESPONSE_POLICY,kind='RESPONSE',**self.scope,operation=request['operation'],
                nonce=request['nonce'],request_sha256=digest(receipt),tip=history['tip'],
                status='HEAD' if request['operation']=='HEAD' else 'COMMITTED',
                issued_at=now.isoformat(),expires_at=(now+LIFETIME).isoformat())
            return J._sign(response,self.signer,self.key_id,RESPONSE_POLICY)


class WitnessClient:
    """Challenge-bound transport consumer; no cached-tip or outage fallback."""
    def __init__(self,*,witness_id,registry_id,journal_anchor,signer,key_id,writer_keys,witness_keys,exchange):
        self.scope=_scope(witness_id,registry_id,journal_anchor)
        self.signer,self.key_id=signer,key_id;self.writer_keys,self.witness_keys=dict(writer_keys),dict(witness_keys)
        require(callable(exchange) and bool(witness_keys) and
            not set(writer_keys.values())&set(witness_keys.values()),'Independent witness transport and key pins required.')
        public=signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        require(self.writer_keys.get(key_id)==public,'Witness client writer key differs.')
        self.exchange=exchange

    def _call(self,operation,expected=None,proposed=None):
        now=J._now()
        value=dict(policy=REQUEST_POLICY,kind='REQUEST',**self.scope,operation=operation,
            nonce=secrets.token_hex(32),expected_tip=deepcopy(expected),proposed_tip=deepcopy(proposed),
            issued_at=now.isoformat(),expires_at=(now+LIFETIME).isoformat())
        request=J._sign(value,self.signer,self.key_id,REQUEST_POLICY)
        _request(request,self.writer_keys,self.scope,now)
        # Transport must not mutate the challenge that the verifier compares.
        response=J._verify(deepcopy(self.exchange(deepcopy(request))),self.witness_keys,
            RESPONSE_FIELDS,'RESPONSE',RESPONSE_POLICY)
        require(all(response[key]==self.scope[key] for key in SCOPE) and
            response['operation']==operation and response['nonce']==value['nonce'] and
            response['request_sha256']==digest(request) and
            response['status']==('HEAD' if operation=='HEAD' else 'COMMITTED'),
            'Witness response challenge, status or scope differs.')
        R._pin(response['tip'])
        issued,expires=J._time(response['issued_at']),J._time(response['expires_at'])
        current=J._now()
        require(now<=issued<=current<expires and current<J._time(value['expires_at']) and
            expires==issued+LIFETIME,'Witness response expired or clock differs.')
        require(operation=='HEAD' or response['tip']==proposed,'Witness acknowledgment tip differs.')
        return deepcopy(response['tip'])

    def head(self):return self._call('HEAD')

    def advance(self,expected,proposed):return self._call('CAS',expected,proposed)


class WitnessedCheckpointRegistry:
    """Use fresh independent witness state for reads, writes and recovery."""
    def __init__(self,registry,client):
        require(client.scope['registry_id']==registry.registry_id and
            client.scope['journal_anchor']==registry.anchor and
            client.writer_keys==registry.registry_keys,'Witness client registry binding differs.')
        roles=set(registry.registry_keys.values())|set(registry.recorder_keys.values())|set(registry.observation_keys.values())|set(registry.recovery_keys.values())
        require(not roles&set(client.witness_keys.values()),'Witness authority must have a separate key domain.')
        self.registry,self.client=registry,client

    def _acknowledge(self,expected,proposed):
        R._pin(expected);R._pin(proposed)
        require(proposed is not None and proposed['sequence']==(expected['sequence']+1 if expected else 1),
            'Witness integration cannot skip registry entries.')
        registry=self.registry
        with registry._locked():
            registry._selection(registry._entries(proposed),proposed)
            if expected:
                require(registry._registry_files().get(f"entry-{expected['sequence']:08d}.encrypted.json")==expected['sha256'],
                    'Published registry does not preserve witness prefix.')
            for root in (registry.journal_root,registry.root):
                fd=os.open(root,os.O_RDONLY)
                try:os.fsync(fd)
                finally:os.close(fd)
            acknowledged=self.client.advance(expected,proposed)
            require(self.client.head()==acknowledged,'Witness advanced before acknowledgment completed.')
            registry._selection(registry._entries(acknowledged),acknowledged)
            return acknowledged

    def select(self):
        tip=self.client.head();registry=self.registry
        with registry._locked():
            registry._selection(registry._entries(tip),tip)
            require(self.client.head()==tip,'Witness advanced during selection.')
            return registry._selection(registry._entries(tip),tip)

    def register(self,*,checkpoint_file,checkpoint_sha256):
        expected=self.client.head()
        proposed=self.registry.register(expected,checkpoint_file=checkpoint_file,checkpoint_sha256=checkpoint_sha256)
        if proposed==expected:
            require(self.select()['registry_tip']==expected,'Witness advanced during idempotent registration.')
            return proposed
        return self._acknowledge(expected,proposed)

    def recover(self,authorization,*,recorder_signer,recorder_key_id):
        expected=self.client.head()
        outcome=self.registry.recover(expected,authorization,recorder_signer=recorder_signer,recorder_key_id=recorder_key_id)
        outcome['registry_tip']=self._acknowledge(expected,outcome['registry_tip'])
        return outcome

    def reconcile(self,authorization):
        expected=self.client.head()
        outcome=self.registry.reconcile_published_tip(expected,authorization)
        outcome['registry_tip']=self._acknowledge(expected,outcome['registry_tip'])
        return outcome
