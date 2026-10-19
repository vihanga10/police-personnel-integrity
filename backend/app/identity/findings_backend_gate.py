"""Trusted backend gate for witnessed Fabric findings; public transport is pending.

No request route, activation, provisioning or readiness waiver. The caller is
backend code supplying configured objects, never HTTP-supplied trust or paths.
"""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import base64
from hashlib import sha256
import re
import subprocess

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from app.identity import findings_commitments as C
from app.identity import findings_tip_witness as W
from app.identity.algorithm_snapshot import load_verified_snapshot
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.generate_protected_commitments import load_keys as original_keys
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest, encoded

POLICY = 'PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1'
ACTIONS = frozenset(('ENTRY','INTENT','PREPARE','READ','ENDORSE','RETAIN',
    'BEFORE_ATTEMPT','BEFORE_SUBMIT','SUBMIT','ACK','OBSERVE','RECONCILE','FINAL','RETURN'))


def committed_repository(repo, revision):
    require(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision),
            'Full committed revision required.')
    repo = Path(repo).expanduser().resolve()
    def git(*args):
        return subprocess.check_output(['git','-C',str(repo),*args],
            stderr=subprocess.DEVNULL, timeout=10, text=True).strip()
    require(git('rev-parse','HEAD') == revision and not git('status','--porcelain', '--untracked-files=all'),
            'Clean committed backend checkout required.')
    return repo


def verify_approval(grant, keys, selection, mode):
    require(type(grant) is dict and set(grant) == {'body','signature'}, 'Exact approval required.')
    body = grant['body']
    require(type(body) is dict and set(body) == {'policy','key_id','mode','issued_at','expires_at','selection'}
        and body['policy'] == POLICY and body['mode'] == mode and body['selection'] == selection,
        'Approved backend selection differs.')
    require(type(body['key_id']) is str and body['key_id'] in keys, 'Backend approver not trusted.')
    key = keys[body['key_id']]
    require(type(key) is bytes and len(key) == 32, 'Pinned Ed25519 approver required.')
    signature = base64.b64decode(grant['signature'], validate=True)
    require(len(signature) == 64 and base64.b64encode(signature).decode() == grant['signature'],
            'Canonical signature required.')
    Ed25519PublicKey.from_public_bytes(key).verify(signature, encoded(body))
    def time(value):
        require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z',value),
                'Canonical millisecond UTC approval required.')
        result = datetime.fromisoformat(value.replace('Z','+00:00'))
        require(result.isoformat(timespec='milliseconds').replace('+00:00','Z') == value,
                'Canonical approval date required.')
        return result
    issued, expires = time(body['issued_at']), time(body['expires_at'])
    require(issued <= datetime.now(timezone.utc) < expires and
        0 < (expires-issued).total_seconds() <= 600, 'Fresh bounded backend approval required.')


def _source(snapshot):
    return digest({k:snapshot[k] for k in ('context','public','manifest','catalog','bindings','envelope')})


class FindingsBackendGate:
    """Fresh full replay per boundary; no externally supplied loaded snapshot.

    EXECUTE requires the exact latest witnessed history. RECONCILE permits an
    older publication only if it is an authenticated prefix of current history.
    Expired readiness stops both modes; this never refreshes an audit permit.
    """
    def __init__(self, args, repo, revision, findings, *, key_file, backup_key_file,
            commitment_directory, private_sha256, public_sha256,
            gateway_config_sha256, destination, mode='RECONCILE'):
        require(mode in ('EXECUTE','RECONCILE'), 'Backend mode differs.')
        require(type(findings) is W.WitnessedFindingsRegistry and findings.fixture_transport is False,
                'Operational findings mTLS witness required.')
        self.repo = committed_repository(repo, revision)
        self.args, self.revision, self.findings = deepcopy(args), revision, findings
        self.key_file, self.backup_key_file = key_file, backup_key_file
        self.directory = commitment_directory
        self.private_pin, self.public_pin = private_sha256, public_sha256
        self.gateway_pin, self.destination, self.mode = gateway_config_sha256, deepcopy(destination), mode
        self._baseline = None
        self._selection = self._verify()

    @property
    def selection(self):
        return deepcopy(self._selection)

    def _verify(self):
        committed_repository(self.repo, self.revision)
        require(type(self.findings) is W.WitnessedFindingsRegistry and self.findings.fixture_transport is False,
                'Operational findings witness configuration changed.')
        self.findings._config()
        snapshot = load_verified_snapshot(self.args, self.repo, self.revision)
        permit = AlgorithmPermit(snapshot); permit.check(snapshot)
        keys, backup = C.load_keys(self.key_file,self.backup_key_file,self.repo)
        original = original_keys(self.args.commitment_key_file,self.args.backup_commitment_key_file,self.repo)
        C._separate(keys,backup,original,self.findings,snapshot)
        summary = C.verify_prepared(self.directory,self.repo,keys,backup,snapshot['crypto'],snapshot['backup'],
            expected_private_sha256=self.private_pin)
        require(summary['public_sha256'] == self.public_pin, 'Public findings commitment differs.')
        _, private = C._read(self.directory,self.repo,snapshot['crypto'],snapshot['backup'],self.private_pin)
        context, history, public = private['context'],private['history'],private['public']
        require(context['source_context'] == snapshot['context'] and
            context['original_publication_sha256'] == digest(snapshot['public']) and
            context['key_pins'] == self.findings.registry.key_pins,
            'Findings source context or authority pins differ.')
        require(self.findings.registry.journal.repo == self.repo and
            self.findings.registry.journal.officer_uid == history['entries'][0]['entry']['officer_uid'] and
            self.findings.registry.journal.officer_uid in {b['officer_uid'] for b in snapshot['manifest']['bundles']},
            'Findings subject outside anchored snapshot.')
        current = self.findings.select()
        require(current['witness_scope'] == history['witness_scope'], 'Findings witness scope differs.')
        if self.mode == 'EXECUTE':
            require(current == history, 'Latest witnessed findings changed; execution blocked.')
        else:
            require(current['entries'][:len(history['entries'])] == history['entries'] and
                current['journal_tip']['ledger_id'] == history['journal_tip']['ledger_id'] and
                current['registry_tip']['registry_id'] == history['registry_tip']['registry_id'],
                'Reconciliation history is not an authenticated current prefix.')
        C.F._sha(self.gateway_pin)
        # The existing gateway validates exact channel/MSP/chaincode pins too.
        require(type(self.destination) is dict and set(self.destination) ==
            {'genesis_sha256','channel','chaincode','namespace','organizations'} and
            self.destination['channel'] == 'personnel' and self.destination['chaincode'] == 'findings-anchor-v1' and
            self.destination['namespace'] == 'findings-anchor-v1' and
            self.destination['organizations'] == ['Org1MSP','Org2MSP'], 'Dedicated Fabric destination required.')
        C.F._sha(self.destination['genesis_sha256'])
        selected = dict(private_sha256=self.private_pin,public_sha256=self.public_pin,
            history_sha256=digest(history),code_revision=self.revision,gateway_config_sha256=self.gateway_pin,
            destination=deepcopy(self.destination),payload=dict(policy='FINDINGS_FABRIC_ANCHOR_V1',
                namespace='findings-anchor-v1',publication_id=public['publication_id'],
                public_sha256=self.public_pin,merkle_root=public['merkle_root'],
                publication_commitment=public['publication_commitment']))
        baseline = digest(dict(source=_source(snapshot),keys=C._key_pin(keys),
            original_keys=digest([original.version,original.content.hex(),original.publication.hex()]),
            scope=self.findings.scope,pins=self.findings.registry.key_pins,selection=selected))
        if self._baseline is None:self._baseline = baseline
        require(self._baseline == baseline, 'Verified backend source or configuration changed.')
        permit.check(snapshot)
        committed_repository(self.repo,self.revision)
        forbidden = {keys.content,keys.publication,original.content,original.publication}
        registry = self.findings.registry; journal = registry.journal
        for crypto in (snapshot['crypto'],snapshot['backup'],registry.crypto,registry.backup,journal.crypto,journal.backup):
            forbidden.update(crypto.encryption_keys.values());forbidden.update(crypto.lookup_keys.values())
        for signer in (journal.signer,registry.signer,self.findings.client.signer):
            forbidden.add(signer.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
        self._forbidden_recovery_keys = {sha256(value).hexdigest() for value in forbidden}
        return selected

    def check_recovery_key(self, value):
        require(type(value) is bytes and len(value) == 32 and
            sha256(value).hexdigest() not in self._forbidden_recovery_keys,
            'Dedicated recovery key must differ from evidence, commitment and signing keys.')

    def check(self, action, selection, mode):
        require(action in ACTIONS and mode == self.mode and selection == self._selection,
                'Protected backend guard scope differs.')
        selected = self._verify()
        require(selected == self._selection, 'Backend selection changed.')
        return deepcopy(selected)
