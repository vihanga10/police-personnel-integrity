"""Separate encrypted checkpoint registry and authorized journal recovery.

Trusted backend only. Latest registry pins must come from independent durable
state. Local files cannot by themselves detect simultaneous full-store rollback.
No keys, live execution, database changes or recovery authorizations are issued.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from datetime import timedelta
from contextlib import contextmanager
import fcntl
import os
import re
import tempfile

from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from app.identity import observed_recording_journal as J
from app.identity.authenticated_recording_history import _scope
from app.identity.bitemporal_reconstruction import RecordingHistory,EvidenceVersion
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest

POLICY='INDEPENDENT_RECORDING_CHECKPOINT_REGISTRY_V1'
RECOVERY_POLICY='RECORDING_CHECKPOINT_RECOVERY_AUTHORIZATION_V1'
FIELDS={'policy','kind','registry_id','journal_anchor','sequence','previous_entry_sha256',
    'checkpoint_file','checkpoint_sha256','event_inventory','preserved_checkpoints','observed_through','registered_at','operation'}
RECOVERY_FIELDS={'policy','kind','registry_id','journal_anchor','registry_tip','artifact_inventory',
    'registry_artifact_inventory','checkpoint_file','issued_at','expires_at','status'}


def _pin(value):
    if value is None:return
    require(type(value) is dict and set(value)=={'sequence','sha256'} and
        type(value['sequence']) is int and value['sequence']>0,'Independent registry tip required.')
    J._hash(value['sha256'])


def _publish(path,receipt,crypto,backup,binding,check):
    """Allow only this write's private staging file during final inventory checks."""
    envelope=J.seal_artifact(crypto,backup,receipt,binding)
    require(J.open_artifact(crypto,envelope,binding)==receipt and
        J.open_artifact(backup,envelope,binding)==receipt,'Registry output recovery differs.')
    data=(J.canonical(envelope)+'\n').encode();temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.registry-',delete=False) as stream:
            temporary=Path(stream.name);os.fchmod(stream.fileno(),0o600)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        check(temporary)
        os.link(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temporary is not None:temporary.unlink(missing_ok=True)
    return sha256(data).hexdigest()


class CheckpointRegistry:
    """One separate registry directory for one journal; no request-facing API.

    Keys, paths, anchor, registry identity and latest expected tip are trusted
    configuration. All participating writers must cooperate with these locks.
    """
    def __init__(self,*,root,journal_root,repo,journal_anchor,registry_id,
            crypto,backup,journal_crypto,journal_backup,signer,key_id,registry_keys,
            recorder_keys,observation_keys,recovery_keys):
        self.root=J._private_root(root,repo);self.journal_root=J._private_root(journal_root,repo)
        require(not self.root.is_relative_to(self.journal_root) and
            not self.journal_root.is_relative_to(self.root),'Registry must be separate from journal.')
        J._hash(journal_anchor);J._text(registry_id)
        self.repo=repo;self.anchor=journal_anchor;self.registry_id=registry_id
        self.crypto=crypto;self.backup=backup;self.journal_crypto=journal_crypto;self.journal_backup=journal_backup
        self.signer=signer;self.key_id=key_id
        self.registry_keys=dict(registry_keys);self.recorder_keys=dict(recorder_keys)
        self.observation_keys=dict(observation_keys);self.recovery_keys=dict(recovery_keys)
        J._recorder(signer,key_id,self.registry_keys,crypto,backup)
        roles=[set(keys.values()) for keys in (registry_keys,recorder_keys,observation_keys,recovery_keys)]
        require(all(not a & b for i,a in enumerate(roles) for b in roles[i+1:]),
            'Registry, recorder, committed-evidence and recovery keys must be separate.')
        registry_secrets=set(crypto.encryption_keys.values())|set(crypto.lookup_keys.values())|set(backup.encryption_keys.values())|set(backup.lookup_keys.values())
        journal_secrets=set(journal_crypto.encryption_keys.values())|set(journal_crypto.lookup_keys.values())|set(journal_backup.encryption_keys.values())|set(journal_backup.lookup_keys.values())
        signing_seed=signer.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
        require(not registry_secrets & journal_secrets and signing_seed not in journal_secrets,
            'Registry secrets must be separate from journal secrets.')

    @contextmanager
    def _locked(self):
        # Fixed order: registry then journal. Journal's ordinary writer uses only the latter.
        roots=(J._private_root(self.root,self.repo),J._private_root(self.journal_root,self.repo))
        descriptors=[]
        try:
            for root in roots:
                fd=os.open(root,os.O_RDONLY);descriptors.append(fd);fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:
            for fd in reversed(descriptors):os.close(fd)

    def _binding(self):
        return dict(artifact='INDEPENDENT_RECORDING_REGISTRY',policy=POLICY,
            registry_id=self.registry_id,journal_anchor=self.anchor)

    def _entries(self,expected_tip,staging=None):
        _pin(expected_tip)
        files=sorted(p for p in self.root.iterdir() if p!=staging)
        # Preserve but block uncertain temporary writes instead of silently skipping them.
        require(all(re.fullmatch(r'entry-[0-9]{8}\.encrypted\.json',p.name) for p in files),
            'Unexpected registry artifact; authenticated recovery required.')
        require(len(files)==(expected_tip['sequence'] if expected_tip else 0),
            'Registry tip is stale, missing or rolled back.')
        previous=None;entries=[];last_time=None
        for index,path in enumerate(files,1):
            require(path.name==f'entry-{index:08d}.encrypted.json','Registry sequence gap.')
            entry_fingerprint,receipt=J._read(path,self.crypto,self.backup,self._binding())
            value=J._verify(receipt,self.registry_keys,FIELDS,'REGISTRY_ENTRY',POLICY)
            require(value['registry_id']==self.registry_id and value['journal_anchor']==self.anchor and
                type(value['sequence']) is int and value['sequence']==index and
                value['previous_entry_sha256']==previous and
                value['operation'] in {'REGISTER','RECOVERY'},'Registry identity or chain differs.')
            now=J._time(value['registered_at']);through=J._time(value['observed_through'])
            require(through<=now<=J._now() and (last_time is None or last_time<=now),
                'Registry recording time order differs.')
            self._inventory_shape(value['event_inventory']);J._hash(value['checkpoint_sha256'])
            self._checkpoint_name(value['checkpoint_file'])
            preserved=value['preserved_checkpoints']
            require(type(preserved) is dict and preserved.get(value['checkpoint_file'])==value['checkpoint_sha256'],
                'Registry preserved checkpoint inventory differs.')
            for name,fingerprint in preserved.items():self._checkpoint_name(name);J._hash(fingerprint)
            if entries:
                prior=entries[-1]
                require(len(value['event_inventory'])>len(prior['event_inventory']) and
                    value['event_inventory'][:len(prior['event_inventory'])]==prior['event_inventory'] and
                    J._time(value['observed_through'])>J._time(prior['observed_through']),
                    'Registry history fork or non-advancing checkpoint.')
                require(all(preserved.get(name)==fingerprint for name,fingerprint in prior['preserved_checkpoints'].items()),
                    'Registered checkpoint preservation differs.')
            entries.append(value);previous=entry_fingerprint;last_time=now
        require(expected_tip is None or previous==expected_tip['sha256'],'Independent registry tip pin differs.')
        return entries

    @staticmethod
    def _checkpoint_name(name):
        require(isinstance(name,str) and re.fullmatch(r'checkpoint-[0-9a-f-]{36}\.encrypted\.json',name),
            'Registry checkpoint filename differs.')

    @staticmethod
    def _inventory_shape(inventory):
        require(type(inventory) is list,'Registry event inventory required.')
        for i,item in enumerate(inventory,1):
            require(type(item) is dict and set(item)=={'file','sha256'} and
                item['file']==f'event-{i:08d}.encrypted.json','Registry ordered event inventory differs.')
            J._hash(item['sha256'])

    def _load(self,name,pin):
        self._checkpoint_name(name);J._hash(pin)
        state=J.load_checkpoint(self.journal_root,self.repo,self.journal_crypto,self.journal_backup,
            self.recorder_keys,self.observation_keys,expected_anchor=self.anchor,
            checkpoint_file=name,expected_checkpoint_digest=pin)
        require(name=='checkpoint-'+state['checkpoint']['checkpoint_id']+'.encrypted.json',
            'Checkpoint filename does not match its signed identity.')
        last=state['history'].versions[-1].recorded_at if state['history'].versions else state['history'].coverage_start
        require(state['history'].coverage_end==last,'Checkpoint cannot extend beyond the last recorded observation.')
        return state

    def _journal_files(self,staging=None):
        files={}
        for path in self.journal_root.iterdir():
            if path==staging:continue
            require(path.name=='baseline.encrypted.json' or
                re.fullmatch(r'event-[0-9]{8}\.encrypted\.json',path.name) or
                re.fullmatch(r'checkpoint-[0-9a-f-]{36}\.encrypted\.json',path.name),
                'Unexpected journal artifact; do not discard uncertain files.')
            require(not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
                path.stat().st_mode & 0o077==0,'Private registry recovery artifact required.')
            files[path.name]=sha256(path.read_bytes()).hexdigest()
        require('baseline.encrypted.json' in files and files['baseline.encrypted.json']==self.anchor,
            'Pinned baseline missing or altered.')
        return files

    def _validate_registered(self,entries):
        # Check all registered predecessors too; retain originals, not only their counts.
        state=None
        for entry in entries:
            state=self._load(entry['checkpoint_file'],entry['checkpoint_sha256'])
            require(state['checkpoint']['event_inventory']==entry['event_inventory'] and
                state['checkpoint']['observed_through']==entry['observed_through'],
                'Registered checkpoint content differs.')
        if entries:
            inventory=entries[-1]['event_inventory']
            for name,fingerprint in entries[-1]['preserved_checkpoints'].items():
                candidate=self._load(name,fingerprint)
                subset=candidate['checkpoint']['event_inventory']
                require(subset==inventory[:len(subset)],'Preserved checkpoint differs from registered history.')
        return state

    def _selection(self,entries,expected_tip):
        require(bool(entries),'Registered journal head required.')
        state=self._validate_registered(entries);files=self._journal_files()
        events={name for name in files if name.startswith('event-')}
        require(events=={i['file'] for i in entries[-1]['event_inventory']},
            'Pending journal events; registry advancement or recovery required.')
        require({name:pin for name,pin in files.items() if name.startswith('checkpoint-')}==
            entries[-1]['preserved_checkpoints'],'Unregistered or changed checkpoint; recovery required.')
        return dict(state=state,registry_tip=deepcopy(expected_tip),
            checkpoint_file=entries[-1]['checkpoint_file'],checkpoint_sha256=entries[-1]['checkpoint_sha256'])

    def select(self,expected_tip):
        """Select only authenticated registry head; pending writes block active use."""
        with self._locked():
            return self._selection(self._entries(expected_tip),expected_tip)

    def _advance(self,entries,expected_tip,state,checkpoint_file,checkpoint_pin,operation,check):
        inventory=state['checkpoint']['event_inventory']
        if entries:
            old=entries[-1]
            if old['checkpoint_file']==checkpoint_file and old['checkpoint_sha256']==checkpoint_pin:
                return deepcopy(expected_tip)
            require(len(inventory)>len(old['event_inventory']) and
                inventory[:len(old['event_inventory'])]==old['event_inventory'] and
                state['history'].coverage_end>J._time(old['observed_through']),
                'Registry update must extend the registered observation history.')
        sequence=len(entries)+1;now=J._now()
        require(state['history'].coverage_end<=now and (not entries or
            now>=J._time(entries[-1]['registered_at'])),'Registry clock moved backwards.')
        value=dict(policy=POLICY,kind='REGISTRY_ENTRY',registry_id=self.registry_id,journal_anchor=self.anchor,
            sequence=sequence,previous_entry_sha256=expected_tip['sha256'] if expected_tip else None,
            checkpoint_file=checkpoint_file,checkpoint_sha256=checkpoint_pin,event_inventory=deepcopy(inventory),
            preserved_checkpoints={name:pin for name,pin in self._journal_files().items() if name.startswith('checkpoint-')},
            observed_through=state['checkpoint']['observed_through'],registered_at=now.isoformat(),operation=operation)
        signed=J._sign(value,self.signer,self.key_id,POLICY)
        fingerprint=_publish(self.root/f'entry-{sequence:08d}.encrypted.json',signed,
            self.crypto,self.backup,self._binding(),check)
        return dict(sequence=sequence,sha256=fingerprint)

    def register(self,expected_tip,*,checkpoint_file,checkpoint_sha256):
        """Register a fully verified completed checkpoint; never infer a latest pin."""
        with self._locked():
            entries=self._entries(expected_tip);self._validate_registered(entries)
            files=self._journal_files();state=self._load(checkpoint_file,checkpoint_sha256)
            require({n for n in files if n.startswith('event-')}==
                {i['file'] for i in state['checkpoint']['event_inventory']},
                'Checkpoint does not cover all preserved journal events.')
            require({n for n in files if n.startswith('checkpoint-')}<=
                (set(entries[-1]['preserved_checkpoints']) if entries else set())|{checkpoint_file},
                'Unregistered alternative checkpoints require authorized recovery.')
            def check(staging):
                self._entries(expected_tip,staging)
                require(self._journal_files()==files,'Journal changed during registry publication.')
                self._load(checkpoint_file,checkpoint_sha256)
            return self._advance(entries,expected_tip,state,checkpoint_file,checkpoint_sha256,'REGISTER',check)

    def _baseline_state(self):
        fingerprint,signed=J._read(self.journal_root/'baseline.encrypted.json',self.journal_crypto,
            self.journal_backup,J._binding('BASELINE'))
        require(fingerprint==self.anchor,'Independent baseline pin differs.')
        base=J._verify(signed,self.recorder_keys,J.BASE_FIELDS,'BASELINE')
        _scope(base['scope']);J._hash(base['original_publication_sha256']);J._hash(base['source_registry_sha256'])
        require(base['semantics']=='RECORDER_OBSERVED_ARCHIVED_BASELINE','Baseline observation semantics differ.')
        start=J._time(base['observed_at']);require(start<=J._now(),'Future baseline refused.')
        require(type(base['claims']) is list,'Baseline claim inventory required.')
        versions=[]
        for entry in base['claims']:
            require(type(entry) is dict and set(entry)=={'claim','source_key'} and
                entry['source_key'] in base['scope']['source_keys'],'Baseline claim entry differs.')
            versions.append(EvidenceVersion('baseline:'+digest(entry),J._claim(entry['claim']),entry['source_key'],
                start,base['journal_id'],self.anchor))
        history=RecordingHistory(base['scope']['officer_uid'],start,start,'baseline-recovery','0'*64,tuple(versions))
        return dict(baseline=base,history=history,last_receipt_sha256=digest(signed))

    def _preserved_history(self,entries,files):
        state=self._validate_registered(entries) if entries else self._baseline_state()
        versions=list(state['history'].versions);previous=state['last_receipt_sha256'];last=state['history'].coverage_end
        inventory=deepcopy(entries[-1]['event_inventory']) if entries else []
        names=sorted(n for n in files if n.startswith('event-'))
        require(names==[f'event-{i:08d}.encrypted.json' for i in range(1,len(names)+1)],
            'Preserved observation sequence gap.')
        for index in range(len(inventory)+1,len(names)+1):
            name=f'event-{index:08d}.encrypted.json'
            fingerprint,receipt=J._read(self.journal_root/name,self.journal_crypto,self.journal_backup,J._binding('EVENT',self.anchor))
            event=J._verify(receipt,self.recorder_keys,J.EVENT_FIELDS,'EVENT')
            require(fingerprint==files[name] and event['journal_anchor']==self.anchor and
                type(event['sequence']) is int and event['sequence']==index and
                event['previous_receipt_sha256']==previous and
                event['semantics']=='RECORDER_OBSERVED_AUTHORIZED_COMMITTED_VERSION',
                'Preserved observation chain differs.')
            observed=J._time(event['observed_at']);require(last<observed<=J._now(),'Preserved observation time differs.')
            approved=J._verify(event['authorization'],self.observation_keys,J.AUTH_FIELDS,'OBSERVATION',J.AUTH_POLICY)
            # Authenticate the original authorization at original observation time; never renew it.
            J._authorization(approved,state['baseline'],self.anchor,observed,self.recorder_keys,self.observation_keys)
            for field in ('claim','source_key','supersedes','withdrawn'):
                require(event[field]==approved[field],'Preserved event differs from authorized evidence.')
            versions.append(EvidenceVersion(event['version_id'],J._claim(event['claim']),event['source_key'],
                observed,event['event_id'],fingerprint,event['supersedes'],event['withdrawn']))
            inventory.append(dict(file=name,sha256=fingerprint));previous,last=digest(receipt),observed
        history=RecordingHistory(state['history'].officer_uid,state['history'].coverage_start,last,
            'authenticated-recovery','0'*64,tuple(versions))
        # Authenticate every extra checkpoint too, including its exact prefix.
        for name in (n for n in files if n.startswith('checkpoint-')):
            candidate=self._load(name,files[name]);candidate_inventory=candidate['checkpoint']['event_inventory']
            require(candidate_inventory==inventory[:len(candidate_inventory)],'Preserved checkpoint forks from event inventory.')
        return history,inventory

    def _registry_files(self,staging=None):
        files={}
        for path in self.root.iterdir():
            if path==staging:continue
            require(re.fullmatch(r'entry-[0-9]{8}\.encrypted\.json',path.name) and
                not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
                path.stat().st_mode & 0o077==0,'Unexpected or non-private registry recovery artifact.')
            files[path.name]=sha256(path.read_bytes()).hexdigest()
        return files

    def _recovery_approval(self,authorization,expected_tip,files,registry_files):
        value=J._verify(authorization,self.recovery_keys,RECOVERY_FIELDS,'RECOVERY',RECOVERY_POLICY)
        _pin(value['registry_tip'])
        require(value['registry_id']==self.registry_id and value['journal_anchor']==self.anchor and
            value['registry_tip']==expected_tip and value['artifact_inventory']==files and
            value['registry_artifact_inventory']==registry_files and
            value['status']=='RECOVERY_AUTHORIZED','Recovery authorization scope differs.')
        issued,expires=J._time(value['issued_at']),J._time(value['expires_at'])
        require(issued<=J._now()<expires and expires==issued+timedelta(seconds=600),
            'Recovery authorization expired or time differs.')
        require(value['checkpoint_file'] is None or value['checkpoint_file'] in files,
            'Recovery checkpoint selection differs.')
        return value

    def recover(self,expected_tip,authorization,*,recorder_signer,recorder_key_id):
        """Reconcile exact authorized preserved bytes; append, never discard or backdate."""
        authorization=deepcopy(authorization)
        with self._locked():
            entries=self._entries(expected_tip);files=self._journal_files()
            registry_files=self._registry_files()
            approval=self._recovery_approval(authorization,expected_tip,files,registry_files)
            J._recorder(recorder_signer,recorder_key_id,self.recorder_keys,self.journal_crypto,self.journal_backup)
            history,inventory=self._preserved_history(entries,files)
            require(not entries or len(inventory)>len(entries[-1]['event_inventory']),
                'Recovery must establish an unregistered observation head.')
            name=approval['checkpoint_file']
            def check_original(staging):
                self._entries(expected_tip);self._recovery_approval(authorization,expected_tip,files,registry_files)
                require(self._registry_files()==registry_files,'Registry changed during recovery.')
                require(self._journal_files(staging)==files,'Recovery artifacts changed before publication.')
            if name is None:
                checkpoint=J._checkpoint(self.anchor,inventory,history.coverage_end.isoformat(),recorder_signer,recorder_key_id)
                name='checkpoint-'+checkpoint['payload']['checkpoint_id']+'.encrypted.json'
                checkpoint_pin=_publish(self.journal_root/name,checkpoint,self.journal_crypto,self.journal_backup,
                    J._binding('CHECKPOINT',self.anchor),check_original)
            else:
                self._checkpoint_name(name);checkpoint_pin=files[name]
            state=self._load(name,checkpoint_pin)
            require(state['checkpoint']['event_inventory']==inventory and
                state['history'].coverage_end==history.coverage_end,'Recovery checkpoint must cover the exact preserved head.')
            updated=dict(files,**{name:checkpoint_pin})
            def check_registry(staging):
                self._entries(expected_tip,staging);self._recovery_approval(authorization,expected_tip,files,registry_files)
                require(self._registry_files(staging)==registry_files,'Registry changed during recovery.')
                require(self._journal_files()==updated,'Recovery artifacts changed before registry publication.')
                self._load(name,checkpoint_pin)
            tip=self._advance(entries,expected_tip,state,name,checkpoint_pin,'RECOVERY',check_registry)
            return dict(registry_tip=tip,checkpoint_file=name,checkpoint_sha256=checkpoint_pin,
                journal_anchor=self.anchor,observation_times_preserved=True)

    def reconcile_published_tip(self,expected_tip,authorization):
        """Recover an entry published before the caller durably acknowledged its tip.

        Approval binds the exact registry/journal bytes and old trusted prefix.
        This does not infer an independently trusted tip from local files alone.
        """
        authorization=deepcopy(authorization);_pin(expected_tip)
        with self._locked():
            files=self._journal_files();registry_files=self._registry_files()
            approval=self._recovery_approval(authorization,expected_tip,files,registry_files)
            old_sequence=expected_tip['sequence'] if expected_tip else 0
            require(len(registry_files)>old_sequence,'No unacknowledged registry entry to recover.')
            if expected_tip:
                require(registry_files.get(f'entry-{old_sequence:08d}.encrypted.json')==expected_tip['sha256'],
                    'Recovery does not retain the independently pinned registry prefix.')
            candidate=dict(sequence=len(registry_files),sha256=registry_files[f'entry-{len(registry_files):08d}.encrypted.json'])
            entries=self._entries(candidate)
            require(approval['checkpoint_file']==entries[-1]['checkpoint_file'],'Recovery must select the published head.')
            self._selection(entries,candidate)
            self._recovery_approval(authorization,expected_tip,files,registry_files)
            require(self._journal_files()==files and self._registry_files()==registry_files,
                'Recovery artifacts changed during reconciliation.')
            # A prior hard link may have succeeded before its directory flush failed.
            # Establish durability before acknowledging the preserved published tip.
            for root in (self.journal_root,self.root):
                fd=os.open(root,os.O_RDONLY)
                try:os.fsync(fd)
                finally:os.close(fd)
            self._recovery_approval(authorization,expected_tip,files,registry_files)
            require(self._journal_files()==files and self._registry_files()==registry_files,
                'Recovery artifacts changed before acknowledgment.')
            return dict(registry_tip=candidate,checkpoint_file=entries[-1]['checkpoint_file'],
                checkpoint_sha256=entries[-1]['checkpoint_sha256'],journal_anchor=self.anchor,
                observation_times_preserved=True)
