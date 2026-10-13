"""Operator-only original-dataset connection. No HTTP route or readiness waiver.

Check is local and read-only. Verify/export use the unchanged full original
replay loader. Import validates every signed item before updating only the
separate access/workspace stores; an interrupted import is explicitly resumable.
"""
import base64
from copy import deepcopy
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.access.policy import account, encoded, label, permitted, require, uid
from app.access.store import private
from app.access import directory as D, research_policy as P, research_bridge as B
from app.access import research_connection_runtime as R
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.protected_commitment import digest
from app.identity.public_anchor_authorization import PUBLIC_SHA

POLICY = 'OPERATIONAL_RESEARCH_CONNECTION_V1'
AUTH_POLICY = 'RESEARCH_DATA_USE_AUTHORIZATION_V1'
CONFIG_MAX_BYTES = 16 * 1024 * 1024
SOURCE_ARTIFACT_MAX_BYTES = 2 * 1024 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024


def file_digest(path, repo, maximum):
    """Hash every byte using bounded chunks; reject replacement/growth during read."""
    p = private(path, repo=repo)
    before = p.stat()
    require(before.st_size <= maximum, 'Bounded configuration input required' if
            maximum == CONFIG_MAX_BYTES else 'Bounded source artifact required')
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_uid, s.st_nlink)
    hasher = hashlib.sha256(); total = 0
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        require(identity(os.fstat(stream.fileno())) == identity(before), 'Connection input changed while opening')
        while True:
            chunk = stream.read(HASH_CHUNK_BYTES)
            if not chunk: break
            total += len(chunk)
            require(total <= maximum, 'Connection input exceeded its size bound')
            hasher.update(chunk)
        require(total == before.st_size and identity(os.fstat(stream.fileno())) == identity(before),
                'Connection input changed while hashing')
    require(identity(private(p, repo=repo).stat()) == identity(before), 'Connection input replaced while hashing')
    return hasher.hexdigest()


SOURCE_FIELDS = ('key_file', 'backup_key_file', 'commitment_key_file',
    'backup_commitment_key_file', 'bundle_attempt', 'binding_attempt',
    'commitment_attempt', 'audit_gate_attempt')


def revision(repo):
    require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'],
        text=True).strip(), 'Committed clean source required')
    return subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()


def authorization(envelope, keys, *, revision, officers, now=None):
    now = time.time() if now is None else now
    R.fields(envelope, ('key_id', 'payload', 'signature'))
    require(envelope['key_id'] in keys, 'Unknown data-use authority')
    p = R.fields(envelope['payload'], ('policy', 'kind', 'issued_at', 'expires_at',
        'source_public_sha256', 'code_revision', 'purpose', 'directory_all_officers',
        'detail_officer_uids', 'review_reference', 'custodian_reference'))
    require(p['policy'] == AUTH_POLICY and p['kind'] == 'DATA_USE' and
        p['source_public_sha256'] == PUBLIC_SHA and p['code_revision'] == revision and
        p['purpose'] == 'SCOPED_RESEARCH_UI' and p['directory_all_officers'] is True,
        'Data-use authorization purpose, source or revision differs')
    require(type(p['issued_at']) is int and type(p['expires_at']) is int and
        p['issued_at'] <= now < p['expires_at'] <= p['issued_at'] + 86400,
        'Current bounded data-use authorization required')
    label(p['review_reference']); label(p['custodian_reference'])
    allowed = p['detail_officer_uids']
    require(allowed == 'ALL' or (type(allowed) is list and len(allowed) <= 6596 and
        len(set(allowed)) == len(allowed)), 'Explicit detail authorization required')
    if type(allowed) is list:
        for officer in allowed: uid(officer)
        require(set(officers) <= set(allowed), 'Officer detail use is not authorized')
    Ed25519PublicKey.from_public_bytes(keys[envelope['key_id']]).verify(
        base64.b64decode(envelope['signature'], validate=True), encoded(p))
    return p


class Connection:
    def __init__(self, config_file):
        self.stage = 'CONFIGURATION'
        self.file = private(config_file)
        c = R.fields(R.read_json(self.file, None), ('policy', 'repository', 'source',
            'access_config', 'workspace_config', 'data_authorization', 'authorization_keys', 'officers'))
        require(c['policy'] == POLICY, 'Connection policy differs')
        self.repo = Path(c['repository']).expanduser().resolve()
        private(self.file, repo=self.repo)
        self.c = deepcopy(c); self.pins = {}; self.bounds = {}; self._watch(self.file)
        R.fields(c['source'], SOURCE_FIELDS)
        for name, path in c['source'].items():
            require(type(path) is str and Path(path).is_absolute(), 'Absolute source paths required')
            private(path, directory=name.endswith('_attempt'), repo=self.repo)
            if not name.endswith('_attempt'): self._watch(path)
        self.args = SimpleNamespace(**{k: Path(v) for k, v in c['source'].items()})
        self.access_config = R.read_json(c['access_config'], self.repo); self._watch(c['access_config'])
        self.workspace_config = R.read_json(c['workspace_config'], self.repo); self._watch(c['workspace_config'])
        R.fields(self.access_config, ('policy', 'repository', 'state_directory', 'key_file', 'authority_keys', 'origin'))
        workspace_fields = ('policy', 'access_config', 'state_directory', 'key_file', 'presentation_keys')
        if 'accountability_config' in self.workspace_config: workspace_fields += ('accountability_config',)
        if 'workflow_assessment_keys' in self.workspace_config:workspace_fields+=('workflow_assessment_keys',)
        R.fields(self.workspace_config, workspace_fields)
        require(self.access_config['policy'] == 'SCOPED_ACCESS_CONFIG_V1' and
            Path(self.access_config['repository']).resolve() == self.repo and
            self.workspace_config['policy'] == 'RESEARCH_WEB_CONFIG_V1' and
            private(self.workspace_config['access_config'], repo=self.repo) == private(c['access_config'], repo=self.repo),
            'Access/workspace/repository configuration differs')
        from app.access.api import origin_url
        origin_url(self.access_config['origin'])
        self.access_keys = R.public_keys(self.access_config['authority_keys'])
        self.workspace_keys = R.public_keys(self.workspace_config['presentation_keys'])
        self.authorization_keys = R.public_keys(c['authorization_keys'])
        if 'workflow_assessment_keys' in self.workspace_config:
            workflow_keys=R.public_keys(self.workspace_config['workflow_assessment_keys'])
            require(len(workflow_keys)<=16 and not set(workflow_keys.values()) &
                (set(self.access_keys.values())|set(self.workspace_keys.values())|set(self.authorization_keys.values())),
                'Separate workflow assessor authority required')
        require(not set(self.authorization_keys.values()) & (set(self.access_keys.values()) | set(self.workspace_keys.values())),
            'Data-use approval key domain must be separate')
        keys = []
        for config in (self.access_config, self.workspace_config):
            private(config['state_directory'], directory=True, repo=self.repo)
            self._watch(config['key_file']); key = private(config['key_file'], repo=self.repo).read_bytes()
            require(len(key) == 32, 'Dedicated 32-byte UI store keys required'); keys.append(key)
        require(keys[0] != keys[1], 'Separate access/workspace encryption keys required')
        roots = [Path(x['state_directory']).resolve() for x in (self.access_config, self.workspace_config)]
        require(not roots[0].is_relative_to(roots[1]) and not roots[1].is_relative_to(roots[0]), 'UI stores overlap')
        if 'accountability_config' in self.workspace_config:
            path = self.workspace_config['accountability_config']; self._watch(path)
            logs = R.read_json(path, self.repo)
            R.fields(logs, ('policy', 'state_directory', 'key_file', 'reader_grants'))
            require(logs['policy'] == 'ACCOUNTABILITY_CONFIG_V1', 'Accountability configuration differs')
            root = private(logs['state_directory'], directory=True, repo=self.repo)
            require(all(not root.is_relative_to(r) and not r.is_relative_to(root) for r in roots), 'Log/UI stores overlap')
            self._watch(logs['key_file'])
            key = private(logs['key_file'], repo=self.repo).read_bytes()
            require(len(key) == 32 and key not in keys, 'Separate log encryption key required')
            require(type(logs['reader_grants']) is list and len(logs['reader_grants']) <= 20, 'Bounded log reader grants required')
            for grant in logs['reader_grants']: self._watch(grant)
        require(type(c['officers']) is dict and len(c['officers']) <= 6596, 'Bounded per-officer runtime map required')
        for officer, runtime in c['officers'].items():
            uid(officer); R.fields(runtime, ('recording_config', 'findings_config'))
            self._runtime_pins(runtime['recording_config'])
            if runtime['findings_config'] is not None: self._runtime_pins(runtime['findings_config'])
        self.envelope = R.read_json(c['data_authorization'], self.repo); self._watch(c['data_authorization'])

    def _watch(self, path, *, source_artifact=False):
        p = private(path, repo=self.repo)
        require(type(source_artifact) is bool, 'Explicit artifact watch mode required')
        if source_artifact:
            require(p == private(self.args.binding_attempt / 'destination-bindings.encrypted.json', repo=self.repo),
                    'Large artifact watch is reserved for configured destination bindings')
        maximum = SOURCE_ARTIFACT_MAX_BYTES if source_artifact else CONFIG_MAX_BYTES
        require(p not in self.bounds or self.bounds[p] == maximum, 'Connection input bound changed')
        pin = file_digest(p, self.repo, maximum)
        require(p not in self.pins or self.pins[p] == pin, 'Previously pinned connection input changed')
        self.pins[p] = pin; self.bounds[p] = maximum

    def _runtime_pins(self, path):
        self._watch(path)
        value = R.read_json(path, self.repo)
        # Base64 public key pins can start with '/'. Only explicit path fields
        # are files; interpreting arbitrary strings as paths is incorrect.
        if value['policy'] == 'RESEARCH_RECORDING_RUNTIME_V1':
            roots = [value['registry_root'], value['journal_root']]
            pairs = [value['registry_crypto'], value['journal_crypto']]
            files = [value['signing_key']]; w = value['witness']
        else:
            require(value['policy'] == 'RESEARCH_FINDINGS_RUNTIME_V1', 'Runtime policy differs')
            roots = [value[k]['root'] for k in ('journal', 'registry')]
            pairs = [value[k]['crypto'] for k in ('journal', 'registry')]
            files = [value[k]['signing_key'] for k in ('journal', 'registry')]; w = value['registry']['witness']
        for root in roots: R.private(root, directory=True, repo=self.repo)
        for pair in pairs:
            R.fields(pair, ('primary', 'backup')); files += list(pair.values())
        files += [w[k] for k in ('profile', 'ca_certificate', 'client_certificate', 'client_key')]
        for file in files: self._watch(R.private(file, repo=self.repo))

    def unchanged(self, selected):
        self.stage = 'INPUT_REVALIDATION'
        require(revision(self.repo) == self.rev, 'Source revision advanced')
        for p, pin in self.pins.items():
            require(file_digest(p, self.repo, self.bounds[p]) == pin,
                    'Connection input changed')
        authorization(self.envelope, self.authorization_keys, revision=self.rev, officers=selected)

    def check(self, selected=()):
        require(len(selected) == len(set(selected)) <= 100, 'At most 100 distinct officer details per connection operation')
        for officer in selected:
            uid(officer); require(officer in self.c['officers'], 'Recording runtime is not configured for this officer')
        self.stage = 'SOURCE_REVISION'
        self.rev = revision(self.repo)
        self.stage = 'DATA_USE_AUTHORIZATION'
        authorization(self.envelope, self.authorization_keys, revision=self.rev, officers=selected)
        self.stage = 'ORIGINAL_SOURCE_ARTIFACTS'
        public_file = self.args.commitment_attempt / 'public-commitments.json'
        binding_file = self.args.binding_attempt / 'destination-bindings.encrypted.json'
        permit_file = self.args.audit_gate_attempt / 'audit-permit.encrypted.json'
        self._watch(public_file)
        self._watch(binding_file, source_artifact=True)
        self._watch(permit_file)
        public = R.read_json(public_file, self.repo)
        require(digest(public) == PUBLIC_SHA, 'Exact original publication required')
        from app.identity.audit_gate import require_audit_permit
        self.stage = 'RECOVERY_AND_KEY_SEPARATION'
        crypto, backup = R.crypto_pair({'primary': str(self.args.key_file), 'backup': str(self.args.backup_key_file)}, self.repo)
        from app.identity.generate_protected_commitments import load_keys
        commitments = load_keys(self.args.commitment_key_file, self.args.backup_commitment_key_file, self.repo)
        commitments.assert_separate(crypto); commitments.assert_separate(backup)
        secrets = {commitments.content, commitments.publication, *crypto.encryption_keys.values(),
            *crypto.lookup_keys.values(), *backup.encryption_keys.values(), *backup.lookup_keys.values()}
        require(all(private(c['key_file'], repo=self.repo).read_bytes() not in secrets
                    for c in (self.access_config, self.workspace_config)), 'UI store keys must be separate from source keys')
        context = dict(code_revision=self.rev, bundle_attempt_id=self.args.bundle_attempt.name,
            binding_attempt_id=self.args.binding_attempt.name, commitment_attempt_id=self.args.commitment_attempt.name,
            binding_artifact_sha256=self.pins[private(binding_file, repo=self.repo)])
        self.stage = 'FRESH_AUDIT_PERMIT'
        require_audit_permit(R.read_json(permit_file, self.repo), crypto, backup, public, context)
        self.unchanged(selected)
        return {'status': 'LOCAL_PRECONDITIONS_VERIFIED', 'source_replay_verified': False,
                'witnesses_verified': False, 'ui_connected': False, 'code_revision': self.rev}

    def _snapshot(self, selected):
        self.check(selected)
        from app.identity.algorithm_snapshot import load_verified_snapshot
        self.stage = 'FULL_ORIGINAL_BATCH_REPLAY'
        snapshot = load_verified_snapshot(self.args, self.repo, self.rev)
        require(snapshot['context']['code_revision'] == self.rev and digest(snapshot['public']) == PUBLIC_SHA,
                'Loader result differs from original configured source')
        self.unchanged(selected)
        return snapshot

    def _presentation(self, snapshot, officer, generation):
        self.stage = 'OPERATIONAL_RECORDING_WITNESS'
        runtime = self.c['officers'][officer]
        recording = R.recording(runtime['recording_config'], self.repo)
        from app.identity.protected_findings_capture import _recording_transport
        _recording_transport(recording, self.repo)
        self.stage = 'OPERATIONAL_FINDINGS_WITNESS'
        findings = R.findings(runtime['findings_config'], self.repo, officer) if runtime['findings_config'] else None
        self.stage = 'BOUND_HISTORY_EXPORT'
        return B._export_loaded(snapshot, self.repo, recording, officer_uid=officer,
                                generation=generation, findings=findings)

    def export(self, membership_file, *, generation, selections):
        require(type(generation) is int and generation > 0, 'Positive directory generation required')
        for g in selections.values(): require(type(g) is int and g > 0, 'Positive presentation generation required')
        snapshot = self._snapshot(list(selections))
        self.stage = 'REVIEWED_MEMBERSHIP'
        self._watch(membership_file)
        membership = R.read_json(membership_file, self.repo)
        directory = D._from_loaded_snapshot(snapshot, membership, self.access_keys, generation=generation)
        directory['expires_at'] = min(directory['expires_at'], self.envelope['payload']['expires_at'])
        presentations = {}
        for officer, g in selections.items():
            presentations[officer] = self._presentation(snapshot, officer, g)
            presentations[officer]['expires_at'] = min(presentations[officer]['expires_at'], self.envelope['payload']['expires_at'])
            self.unchanged(list(selections)); AlgorithmPermit(snapshot).check(snapshot)
        self.unchanged(list(selections)); AlgorithmPermit(snapshot).check(snapshot)
        return {'policy': POLICY, 'code_revision': self.rev, 'source_public_sha256': PUBLIC_SHA,
            'data_authorization_sha256': digest(self.envelope), 'directory': directory,
            'presentations': presentations, 'signed': False, 'ui_connected': False}

    def verify(self, selected=()):
        snapshot = self._snapshot(list(selected))
        for officer in selected: self._presentation(snapshot, officer, 1)
        self.unchanged(list(selected)); AlgorithmPermit(snapshot).check(snapshot)
        return {'status': 'ORIGINAL_SOURCE_REPLAY_VERIFIED', 'officers': len(snapshot['manifest']['bundles']),
            'witnesses_verified_for_selected_officers': len(selected), 'ui_connected': False,
            'code_revision': self.rev, 'source_public_sha256': PUBLIC_SHA}

    def membership_draft(self, review_reference):
        """Private all-officer worksheet. NULL explicitly means unknown scope.

        No CSV posting/date/rank is converted into an access grant. An appointed
        administrator must review the current scope map and sign it separately.
        """
        label(review_reference)
        snapshot = self._snapshot([])
        officers = sorted(b['officer_uid'] for b in snapshot['manifest']['bundles'])
        require(len(officers) == len(set(officers)), 'Repeated anchored officer')
        for officer in officers: uid(officer)
        now = int(time.time())
        result = dict(policy=D.POLICY, kind='MEMBERSHIP', issued_at=now,
            expires_at=min(now + 3600, self.envelope['payload']['expires_at']),
            source_public_sha256=PUBLIC_SHA, officers=[dict(officer_uid=o,
                membership={level: None for level in D.LEVELS}) for o in officers],
            review_reference=review_reference)
        self.unchanged([]); AlgorithmPermit(snapshot).check(snapshot)
        return result

    def install(self, directory, presentations, disclosures):
        """Resumable signed cache import; all source/permission checks precede writes.

        SQLite stores have separate transactions. There is no cross-store atomicity
        claim. A crash can leave a directory/packet installed without disclosure;
        the web API withholds details, and exact current items can be reimported.
        """
        require(type(presentations) is list and type(disclosures) is list and
                len(presentations) <= 100 and len(disclosures) <= 1000, 'Bounded connection import required')
        selected = [p['payload']['officer_uid'] for p in presentations]
        snapshot = self._snapshot(selected)
        return self._install_loaded(snapshot, directory, presentations, disclosures)

    def _install_loaded(self, snapshot, directory, presentations, disclosures):
        """Internal operator pipeline: reuse its one full replay, never HTTP input."""
        require(type(presentations) is list and type(disclosures) is list and
                len(presentations) <= 100 and len(disclosures) <= 1000, 'Bounded connection import required')
        selected = [p['payload']['officer_uid'] for p in presentations]
        self.check(selected)
        require(snapshot['context']['code_revision'] == self.rev and
                snapshot['envelope'] == R.read_json(self.args.audit_gate_attempt / 'audit-permit.encrypted.json', self.repo),
                'Loaded replay and configured audit permit differ')
        AlgorithmPermit(snapshot).check(snapshot)
        self.stage = 'SIGNED_DIRECTORY_BINDING'
        d = D.validate_directory(directory, self.access_keys)
        generated = self.envelope['payload']['custodian_reference'] == 'GENERATED_RECORD_OWNER_NOT_POLICE_CUSTODIAN'
        require(d['source_public_sha256'] == PUBLIC_SHA and ((generated and d['expires_at'] is None) or
                (d['expires_at'] is not None and d['expires_at'] <= self.envelope['payload']['expires_at'])),
                'Directory source or data-use expiry differs')
        # Authenticate the directory against a complete source replay, not just
        # its trusted administrator signature or an officer-count comparison.
        # Rebuild identity projection independently; never fabricate a membership
        # signature. The original signed directory supplies the reviewed scope map.
        expected = self._identities(snapshot)
        actual = {o['officer_uid']: {k: v for k, v in o.items() if k != 'membership'} for o in d['officers']}
        require(actual == expected, 'Signed directory identities differ from original replay')
        packets = {}; grants = []
        for envelope in presentations:
            self.stage = 'SIGNED_PRESENTATION_BINDING'
            p = P.packet(envelope, self.workspace_keys, time.time())
            require(p['source_public_sha256'] == PUBLIC_SHA and ((generated and p['expires_at'] is None) or
                    (p['expires_at'] is not None and p['expires_at'] <= self.envelope['payload']['expires_at'])),
                    'Presentation source or data-use expiry differs')
            if p['expires_at'] is not None:
                require(p['expires_at'] <= p['issued_at'] + 300, 'Operational presentation lifetime exceeds five minutes')
            else:
                require(p['full_records'] == P.full_records(snapshot,p['officer_uid']), 'Full source details differ from original replay')
            current = self._presentation(snapshot, p['officer_uid'], p['generation'])
            require(all(p[k] == current[k] for k in ('history', 'findings', 'authority', 'recording_tip_sha256', 'anchoring')),
                    'Presentation no longer matches current protected observations')
            require(p['officer_uid'] not in packets, 'Duplicate officer presentation')
            packets[p['officer_uid']] = (envelope, p)
        seen = set()
        for envelope in disclosures:
            self.stage = 'SIGNED_DISCLOSURE_BINDING'
            p = P.grant(envelope, self.workspace_keys, time.time())
            require(p['officer_uid'] in packets and p['source_public_sha256'] == PUBLIC_SHA and
                    p['expires_at'] <= self.envelope['payload']['expires_at'],
                    'Disclosure needs a selected original-source presentation')
            pair = (p['user_id'], p['officer_uid']); require(pair not in seen, 'Duplicate disclosure'); seen.add(pair)
            grants.append((envelope, p))
        self.unchanged(selected); AlgorithmPermit(snapshot).check(snapshot)
        from app.access.research_app import configured
        self.stage = 'UI_STORE_CONFIGURATION'
        store, _ = configured(self.c['workspace_config'])
        require(store.repo == self.repo and store.access.keys == self.access_keys and
                store.keys == self.workspace_keys, 'Configured UI stores differ')
        self.stage = 'ACCOUNT_SCOPE_AND_DISCLOSURE'
        self._validate_accounts(store, d, grants)
        self.unchanged(selected); AlgorithmPermit(snapshot).check(snapshot)
        lock_path = store.root / 'connection-import.lock'
        try:
            with lock_path.open('xb') as file: os.fchmod(file.fileno(), 0o600)
        except FileExistsError: private(lock_path, repo=self.repo)
        with private(lock_path, repo=self.repo).open('rb') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            # Check conflicts for the whole operation before changing any cache.
            self._validate_accounts(store, d, grants)
            self.stage = 'CACHE_GENERATION_CONFLICTS'
            self._validate_generations(store, directory, packets, grants)
            self.unchanged(selected); AlgorithmPermit(snapshot).check(snapshot)
            with store.access.transaction() as c:
                old = c.execute('SELECT version,value FROM directory WHERE id=1').fetchone()
                same = old and old[0] == d['generation'] and store.access.open('DIRECTORY', 1, old[0], old[1]) == directory
            self.stage = 'RESUMABLE_CACHE_WRITE'
            if not same: store.access.put_directory(directory)
            for envelope, _ in packets.values():
                self.unchanged(selected); AlgorithmPermit(snapshot).check(snapshot); store.import_packet(envelope)
            for envelope, _ in grants:
                self.unchanged(selected); AlgorithmPermit(snapshot).check(snapshot)
                self._validate_accounts(store, d, [(envelope, envelope['payload'])]); store.import_grant(envelope)
        return {'status': 'SIGNED_UI_CACHE_IMPORTED', 'directory_officers': len(d['officers']),
            'presentations': len(packets), 'disclosures': len(grants), 'sign_in_again': True,
            'live_public_finality_claim': False, 'research_storage_changed': False}

    @staticmethod
    def _identities(snapshot):
        from app.identity.normalization import normalize_identifier
        officers = {}
        universe = {b['officer_uid'] for b in snapshot['manifest']['bundles']}
        for raw, item in snapshot['catalog'].items():
            if item['filename'] != 'officer_personal_information.csv': continue
            links = [x for x in item['candidate_links'] if x['role'] == 'officer_nic_no']
            require(len(links) == 1 and links[0]['state'] == 'CANDIDATE_NOT_ACCEPTED' and
                item['delivery']['complete'] is True and raw == item['raw_record_id'] and
                snapshot['bindings']['raw_bindings'].get(raw), 'Original profile binding differs')
            officer = links[0]['officer_uid']; require(officer in universe and officer not in officers, 'Profile subject differs')
            original = item['original']; columns, values = original['columns'], original['values']
            require(len(columns) == len(set(columns)) == len(values) and all(type(x) is str for x in columns + values), 'Original row differs')
            row = dict(zip(columns, values))
            officers[officer] = dict(officer_uid=officer,
                nic=normalize_identifier(row['officer_nic_no'], identifier_type='NIC').value,
                names=[row[k] for k in ('full_name', 'name_with_initials') if row.get(k, '').strip()], source_raw_id=raw)
        require(set(officers) == universe, 'Every anchored officer needs one bound profile')
        return officers

    @staticmethod
    def _validate_accounts(store, directory, grants):
        from app.security.record_protection import AssignmentProtection, RecordClassification, DisclosureCategory, ProtectionLevel, required_protection
        officers = {o['officer_uid']: o for o in directory['officers']}
        with store.access.transaction() as c:
            for _, g in grants:
                row = c.execute('SELECT id,version,value FROM users WHERE owner=?', (store.access.index('OWNER', g['user_id']),)).fetchone()
                require(row is not None, 'Disclosure account is not provisioned')
                value = store.access.open('USER', row[0], row[1], row[2]); a = account(value['grant'], store.access.keys)
                require(a['active'] and a['user_id'] == g['user_id'] and a['version'] == g['account_version'] and
                    permitted(a, officers[g['officer_uid']]), 'Disclosure account version or scope differs')
                decision = required_protection(assignment=AssignmentProtection(g['assignment']),
                    record_classification=RecordClassification(g['classification']), category=DisclosureCategory.PERSONNEL_DETAILS)
                require(decision.level is not ProtectionLevel.WITHHOLD and
                    (decision.level is not ProtectionLevel.RESTRICTED or g['restricted_clearance']), 'Disclosure classification or clearance unresolved')

    @staticmethod
    def _validate_generations(store, directory, packets, grants):
        d = directory['payload']
        with store.access.transaction() as c:
            row = c.execute('SELECT version,value FROM directory WHERE id=1').fetchone()
            require(row is None or d['generation'] > row[0] or (d['generation'] == row[0] and
                store.access.open('DIRECTORY', 1, row[0], row[1]) == directory), 'Directory generation conflict')
        with store.transaction() as c:
            for envelope, p in packets.values():
                ident = store.index('OFFICER', p['officer_uid'])
                row = c.execute('SELECT version,value FROM presentations WHERE id=?', (ident,)).fetchone()
                require(row is None or p['generation'] > row[0] or (p['generation'] == row[0] and
                    store.open('PACKET', ident, row[1]) == envelope), 'Presentation generation conflict')
            for envelope, p in grants:
                ident = store.index('GRANT', p['user_id'], p['officer_uid'])
                row = c.execute('SELECT issued,value FROM disclosures WHERE id=?', (ident,)).fetchone()
                require(row is None or p['issued_at'] > row[0] or (p['issued_at'] == row[0] and
                    store.open('GRANT', ident, row[1]) == envelope), 'Disclosure issuance conflict')
