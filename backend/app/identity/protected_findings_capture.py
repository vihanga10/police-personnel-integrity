"""Fresh protected contradiction capture into witnessed findings; backend only.

No CLI, endpoint, readiness waiver, acceptance decision or automatic recovery.
Loaded snapshots/configured objects and publication callbacks are internal only.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import date
from pathlib import Path
import json
from app.identity import protected_contradiction_runner as P
from app.identity import findings_tip_witness as A
from app.identity import encrypted_findings_journal as F
from app.identity import observed_recording_journal as J
from app.identity import recording_tip_witness as W
from app.identity import bitemporal_reconstruction as B
from app.identity import bitemporal_contradictions as D
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.historical_source_claims import source_claims,HEADERS
from app.identity.evidence_bundle_v2 import canonical
from app.identity.protected_commitment import digest
from app.identity.historical_reconstruction import require
from app.identity.witness_secure_transport import HTTPSWitnessTransport

POLICY='PROTECTED_CONTRADICTION_FINDINGS_CAPTURE_V1'
INTENT_POLICY='PROTECTED_FINDINGS_CAPTURE_INTENT_V1'
FIELDS={'policy','kind','operation_id','finding_id','officer_uid','ledger_id','registry_id',
    'source_context','publication_sha256','source_sha256','effective_on','known_at','query_digest',
    'comparison_digest','expected_findings_tip','supersedes','reason','receipt_path','created_at'}


def _source(snapshot):return digest(dict(catalog=snapshot['catalog'],bindings=snapshot['bindings']['raw_bindings']))


def _recording_transport(adapter,repo):
    require(type(adapter) is W.WitnessedCheckpointRegistry and type(adapter.client) is W.WitnessClient and
        type(adapter.client.exchange) is HTTPSWitnessTransport,'Configured recording mutual-TLS witness required.')
    transport=adapter.client.exchange
    require(Path(transport.repo).expanduser().resolve()==Path(repo).expanduser().resolve() and
        all(transport.profile[k]==adapter.client.scope[k] for k in W.SCOPE) and
        transport.writer_key_id==adapter.client.key_id and
        transport.profile['writer_keys_sha256']==W._key_digest(adapter.client.writer_keys) and
        transport.profile['witness_keys_sha256']==W._key_digest(adapter.client.witness_keys),
        'Recording witness transport pins differ.')


def capture_contradictions(args,repo,revision,recording,findings,**kwargs):
    """Operational backend entry: both mTLS transports and full replay are mandatory."""
    _recording_transport(recording,repo)
    require(type(findings) is A.WitnessedFindingsRegistry and findings.fixture_transport is False,
        'Operational findings mutual-TLS witness required.')
    findings._config()
    from app.identity.algorithm_snapshot import load_verified_snapshot
    snapshot=load_verified_snapshot(args,repo,revision)
    return capture_loaded(snapshot,repo,recording,findings,**kwargs)


def _serialized(value):return json.loads(json.dumps(asdict(value),default=P._wire,allow_nan=False))


def _verified_source(snapshot,recording,officer_uid,effective_on,known_at):
    selection=recording.select();state=selection['state'];base=state['baseline']
    require(base['scope']['officer_uid']==officer_uid,'Capture officer differs from verified evidence.')
    current=deepcopy(snapshot['context']);original=deepcopy(base['source_context'])
    current.pop('code_revision',None);original.pop('code_revision',None)
    require(current==original and base['original_publication_sha256']==digest(snapshot['public']) and
        base['source_registry_sha256']==digest({k:sorted(v) for k,v in HEADERS.items()}),
        'Capture baseline differs from replayed original evidence.')
    claims=source_claims(officer_uid,snapshot['catalog'],snapshot['bindings']['raw_bindings'])
    expected=[dict(claim=J._wire(c),source_key=json.loads(c.source_reference)['filename']) for c in claims]
    require(sorted(map(canonical,expected))==sorted(map(canonical,base['claims'])),
        'Capture baseline source claims differ.')
    query=B.query(state['history'],effective_on=effective_on,known_at=known_at)
    comparison=D.compare_history(state['history'],effective_on=effective_on,known_at=known_at)
    require(query.query_digest==comparison.query_digest,'Capture comparison history differs.')
    return selection,_serialized(query),_serialized(comparison)


def _binding(operation,ledger):return dict(artifact='PROTECTED_FINDINGS_CAPTURE_INTENT',policy=INTENT_POLICY,operation_id=operation,ledger_id=ledger)


def capture_loaded(snapshot,repo,recording,findings,*,officer_uid,effective_on,known_at,
        operation_id,finding_id,destination,supersedes=None,reason=None):
    """Internal full-replay boundary; fixture transports are never public waivers."""
    require(type(recording) is W.WitnessedCheckpointRegistry and type(findings) is A.WitnessedFindingsRegistry,
        'Trusted recording and findings witnesses required.')
    F._uuid(officer_uid);F._uuid(operation_id);F._uuid(finding_id)
    require(type(effective_on) is date,'Effective calendar date required.')
    known_at=B.instant(known_at);repo=Path(repo).expanduser().resolve();journal=findings.registry.journal
    require(recording.registry.repo==repo and journal.repo==repo and journal.officer_uid==officer_uid,
        'Capture repository or findings officer scope differs.')
    if supersedes is not None:F._sha(supersedes);F._text(reason)
    else:require(reason is None,'Original capture cannot contain a correction reason.')
    require(snapshot['crypto'].encryption_keys==journal.crypto.encryption_keys and
        snapshot['backup'].encryption_keys==journal.backup.encryption_keys,'Capture receipt recovery key domains differ.')
    destination=Path(destination).expanduser().absolute()
    require('..' not in destination.parts,'Capture destination traversal refused.')
    parent=J._private_root(destination.parent,repo)
    intent_path=parent/(destination.name+'.capture-intent.encrypted.json')
    roots=(recording.registry.root,recording.registry.journal_root,findings.registry.root,journal.root)
    for i,root in enumerate(roots):
        require(not parent.is_relative_to(root) and not root.is_relative_to(parent),'Capture staging must be separate from protected stores.')
        for other in roots[i+1:]:require(not root.is_relative_to(other) and not other.is_relative_to(root),
            'Recording and findings stores must not overlap.')
    require(not destination.is_symlink() and not intent_path.is_symlink(),'Capture artifact symlink refused.')
    permit=AlgorithmPermit(snapshot);permit.check(snapshot)
    source_sha=_source(snapshot);context=deepcopy(snapshot['context']);publication_sha=digest(snapshot['public'])
    recording_scope=deepcopy(recording.client.scope)
    recording_keys=(W._key_digest(recording.client.writer_keys),W._key_digest(recording.client.witness_keys))
    _,query,comparison=_verified_source(snapshot,recording,officer_uid,effective_on,known_at)
    request=dict(operation_id=operation_id,finding_id=finding_id,officer_uid=officer_uid,
        ledger_id=journal.ledger_id,registry_id=findings.registry.registry_id,source_context=context,
        publication_sha256=publication_sha,source_sha256=source_sha,effective_on=effective_on.isoformat(),
        known_at=known_at.isoformat(),query_digest=query['query_digest'],comparison_digest=comparison['comparison_digest'],
        supersedes=supersedes,reason=reason,receipt_path=str(destination))
    current=findings.select()
    binding=_binding(operation_id,journal.ledger_id)
    if intent_path.exists():
        _,receipt=J._read(intent_path,journal.crypto,journal.backup,binding)
        intent=J._verify(receipt,journal.writer_keys,FIELDS,'CAPTURE_INTENT',INTENT_POLICY)
        require(all(intent[k]==v for k,v in request.items()),'Capture retry request or verified evidence differs.')
        F._time(intent['created_at'])
    else:
        require(not destination.exists(),'Preexisting receipt cannot become a new protected capture.')
        require(all(e['entry']['operation_id']!=operation_id for e in current['entries']),
            'Capture operation already belongs to existing findings.')
        intent=dict(policy=INTENT_POLICY,kind='CAPTURE_INTENT',**request,
            expected_findings_tip=deepcopy(current['registry_tip']),created_at=J._now().isoformat())
        def intent_check():
            permit.check(snapshot);require(_source(snapshot)==source_sha,'Capture source changed.')
            require(findings.select()['registry_tip']==current['registry_tip'],'Findings changed before capture intent publication.')
        J._publish(intent_path,J._sign(intent,journal.signer,journal.key_id,INTENT_POLICY),journal.crypto,journal.backup,binding,intent_check)

    def validate_receipt():
        permit.check(snapshot)
        require(_source(snapshot)==source_sha and snapshot['context']==context and digest(snapshot['public'])==publication_sha,
            'Capture replay or publication changed.')
        require(recording.client.scope==recording_scope and
            (W._key_digest(recording.client.writer_keys),W._key_digest(recording.client.witness_keys))==recording_keys,
            'Capture recording witness configuration changed.')
        selected,q,c=_verified_source(snapshot,recording,officer_uid,effective_on,known_at)
        require(q==query and c==comparison,'Captured historical result changed.')
        sha,result=F.read_comparison_receipt(destination,repo,journal.crypto,journal.backup,officer_uid)
        envelope=F._json(destination.read_bytes());receipt_binding=envelope['binding']
        require(receipt_binding['source_context']==context and receipt_binding['original_publication_sha256']==publication_sha and
            receipt_binding['journal_anchor']==recording.registry.anchor and receipt_binding['registry_tip']==result['registry_tip'] and
            result['query']==query and result['comparison']==comparison and result['witness_scope']==recording_scope,
            'Capture receipt does not match verified producer intent.')
        old=result['registry_tip'];W.R._pin(old)
        require(old is not None and old['sequence']<=selected['registry_tip']['sequence'] and
            recording.registry._registry_files().get(f"entry-{old['sequence']:08d}.encrypted.json")==old['sha256'],
            'Capture receipt recording prefix is not preserved.')
        # The original checkpoint remains pinned in the latest verified registry.
        with recording.registry._locked():
            entries=recording.registry._entries(selected['registry_tip'])
            require(entries[-1]['preserved_checkpoints'].get(result['checkpoint_file'])==result['checkpoint_sha256'],
                'Capture receipt checkpoint is not preserved.')
        permit.check(snapshot);return sha,result

    if not destination.exists():
        require(current['registry_tip']==intent['expected_findings_tip'],'Findings changed before producer execution.')
        P.run_loaded_comparison(snapshot,repo,recording,officer_uid=officer_uid,effective_on=effective_on,
            known_at=known_at,destination=destination)
    sha,result=validate_receipt()
    # Fresh independent findings selection either proves the operation complete
    # or establishes the exact intent predecessor before a new journal append.
    selected=findings.select();matches=[e for e in selected['entries'] if e['entry']['operation_id']==operation_id]
    if matches:
        require(len(matches)==1,'Repeated capture operation.')
        entry=matches[0]['entry'];kind='CORRECTION' if supersedes is not None else 'FINDING'
        require(entry['kind']==kind and entry['finding_id']==finding_id and entry['receipt_sha256']==sha and
            entry['finding']==result and entry['supersedes']==supersedes and entry['reason']==reason and
            entry['sequence']==intent['expected_findings_tip']['sequence']+1,'Recorded capture differs from signed intent.')
        permit.check(snapshot)
        return dict(policy=POLICY,status='ALREADY_CAPTURED',accepted_state=None,findings_anchored=False)
    require(selected['registry_tip']==intent['expected_findings_tip'],'Findings predecessor changed; capture cannot silently rebase.')
    def before_publish():
        actual_sha,actual_result=validate_receipt()
        require(actual_sha==sha and actual_result==result,'Capture receipt changed before finding publication.')
        require(findings._head()==intent['expected_findings_tip'],'Findings witness advanced before capture publication.')
        permit.check(snapshot)
    findings.append_receipt(operation_id=operation_id,finding_id=finding_id,receipt_path=destination,
        supersedes=supersedes,reason=reason,before_publish=before_publish)
    permit.check(snapshot)
    return dict(policy=POLICY,status='CAPTURED',accepted_state=None,findings_anchored=False)
