"""Protected per-ledger findings commitments; no chain client or key provisioning."""
from copy import deepcopy
from datetime import timezone
from hashlib import sha256
import base64
import hmac
import os
from pathlib import Path
import re
import tempfile
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from app.identity import encrypted_findings_journal as F
from app.identity import findings_tip_witness as W
from app.identity import observed_recording_journal as J
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.evidence_bundle_v2 import open_artifact,canonical
from app.identity.protected_commitment import CommitmentKeys,digest,encoded,merkle_root
from app.identity.historical_reconstruction import require

POLICY='FINDINGS_PROTECTED_COMMITMENTS_V1'
KEY_POLICY='FINDINGS_COMMITMENT_KEYS_V1'
PROOF_POLICY='FINDINGS_MERKLE_PROOF_V1'
KEY_VERSION='findings-commit-v1'
PRIVATE_NAME='findings-commitments.encrypted.json'
PUBLIC_NAME='public-findings-commitments.json'
PUBLIC_FIELDS={'policy','commitment_version','key_version','publication_id','entries',
    'history_commitment','publication_commitment','merkle_root'}
CONTEXT_FIELDS={'source_context','original_publication_sha256','generator_revision','prepared_at','key_pins'}
PRIVATE_FIELDS={'policy','key_version','salt','context','history','public'}


class FindingsCommitmentKeys:
    def __init__(self,data):
        require(type(data) is dict and set(data)=={'policy','version','content_key','publication_key'} and
            data['policy']==KEY_POLICY and data['version']==KEY_VERSION,'Findings commitment key policy differs.')
        self.version=data['version']
        self.content=base64.b64decode(data['content_key'],validate=True)
        self.publication=base64.b64decode(data['publication_key'],validate=True)
        require(len(self.content)==len(self.publication)==32 and not hmac.compare_digest(self.content,self.publication),
            'Separate 32-byte findings commitment keys required.')

    def commit(self,domain,value):
        return hmac.new(self.content,encoded([POLICY,self.version,domain,value]),sha256).hexdigest()

    def handle(self,domain,value):
        return hmac.new(self.publication,encoded([POLICY,self.version,domain,value]),sha256).hexdigest()


def _root(path,repo):
    path=Path(path).expanduser().absolute()
    require('..' not in path.parts,'Findings commitment path traversal refused.')
    return J._private_root(path,repo)


def load_keys(primary,backup,repo):
    paths=[Path(p).expanduser().absolute() for p in (primary,backup)]
    for path in paths:
        _root(path.parent,repo)
        require(not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
            path.stat().st_mode&0o077==0,'Private findings commitment key file required.')
    require(not os.path.samefile(*paths),'Independent findings commitment recovery copies required.')
    data=[F._json(path.read_bytes()) for path in paths];keys=[FindingsCommitmentKeys(x) for x in data]
    require(data[0]==data[1],'Findings commitment recovery differs.')
    return keys[0],keys[1]


def _key_pin(keys):
    require(type(keys) is FindingsCommitmentKeys,'Typed findings commitment keys required.')
    require(keys.version==KEY_VERSION and type(keys.content) is bytes and len(keys.content)==32 and
        type(keys.publication) is bytes and len(keys.publication)==32 and keys.content!=keys.publication,
        'Findings commitment keys changed shape.')
    # Private runtime pin only; never included in public artifacts.
    return digest([keys.version,keys.content.hex(),keys.publication.hex()])


def _separate(keys,backup_keys,original_keys,findings,snapshot):
    require(_key_pin(keys)==_key_pin(backup_keys),'Findings commitment key recovery differs.')
    require(type(original_keys) is CommitmentKeys,'Verified original commitment keys required.')
    require(original_keys.version=='commit-v1' and type(original_keys.content) is bytes and len(original_keys.content)==32 and
        type(original_keys.publication) is bytes and len(original_keys.publication)==32 and original_keys.content!=original_keys.publication,
        'Original commitment keys changed shape.')
    forbidden={original_keys.content,original_keys.publication}
    r=findings.registry;j=r.journal
    for crypto in (snapshot['crypto'],snapshot['backup'],j.crypto,j.backup,r.crypto,r.backup):
        forbidden.update(crypto.encryption_keys.values());forbidden.update(crypto.lookup_keys.values())
    for signer in (j.signer,r.signer,findings.client.signer):
        forbidden.add(signer.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
    for mapping in (j.writer_keys,j.reviewer_keys,j.authority_keys,r.registry_keys,r.recovery_keys,
            findings.client.witness_keys):forbidden.update(mapping.values())
    require(keys.content not in forbidden and keys.publication not in forbidden,
        'Findings commitment keys must be separate from original, encryption, lookup and signing domains.')


def _leaves(public):
    return [dict(kind='FINDINGS_ENTRY',**e) for e in public['entries']]+[
        dict(kind='FINDINGS_HISTORY',policy=POLICY,commitment_version=1,key_version=public['key_version'],
            publication_id=public['publication_id'],history_commitment=public['history_commitment'],
            entry_count=len(public['entries']),commitment=public['publication_commitment'])]


def validate_public(public):
    require(type(public) is dict and set(public)==PUBLIC_FIELDS and public['policy']==POLICY and
        type(public['commitment_version']) is int and public['commitment_version']==1 and
        public['key_version']==KEY_VERSION,'Findings public schema differs.')
    for key in ('publication_id','history_commitment','publication_commitment','merkle_root'):F._sha(public[key])
    entries=public['entries'];require(type(entries) is list and 0<len(entries)<=1000000,'Nonempty bounded findings publication required.')
    for e in entries:
        require(type(e) is dict and set(e)=={'publication_id','commitment'},'Opaque public entry schema differs.')
        F._sha(e['publication_id']);F._sha(e['commitment'])
    handles=[e['publication_id'] for e in entries];commitments=[e['commitment'] for e in entries]
    require(handles==sorted(set(handles)) and len(set(commitments))==len(commitments) and
        public['publication_id'] not in handles,'Repeated or unordered findings publication.')
    require(public['merkle_root']==merkle_root(_leaves(public)),'Findings Merkle root differs.')
    return public


def generate(history,keys,*,salt,context):
    """Pure generation: input authenticity must be supplied by protected preparation."""
    _key_pin(keys)
    require(type(salt) is bytes and len(salt)==32,'Private 32-byte epoch salt required.')
    require(type(context) is dict and set(context)==CONTEXT_FIELDS,'Exact private preparation context required.')
    require(type(context['generator_revision']) is str and re.fullmatch('[0-9a-f]{40}',context['generator_revision']),
        'Committed preparation revision required.')
    F._sha(context['original_publication_sha256']);F._time(context['prepared_at'])
    require(type(history) is dict and history['policy']==W.POLICY and history['accepted_state'] is None and
        history['findings_anchored'] is False,'Reported witnessed findings selection required.')
    entries=history['entries'];require(type(entries) is list and entries,'Empty findings history cannot be published.')
    first=entries[0]['entry'];F._uuid(first['ledger_id']);F._uuid(first['officer_uid'])
    require(history['journal_tip']['ledger_id']==first['ledger_id'] and history['journal_tip']['sequence']==len(entries) and
        history['journal_tip']['entry_sha256']==entries[-1]['entry_sha256'],'Complete ordered findings history required.')
    previous='0'*64
    for sequence,item in enumerate(entries,1):
        require(type(item) is dict and set(item)=={'entry_sha256','entry'},'Exact findings entry required.')
        F._sha(item['entry_sha256']);entry=item['entry']
        require(entry['policy']==F.POLICY and entry['ledger_id']==first['ledger_id'] and
            entry['officer_uid']==first['officer_uid'] and type(entry['sequence']) is int and entry['sequence']==sequence and
            entry['previous_sha256']==previous and entry['kind'] in ('FINDING','CORRECTION','REVIEW'),
            'Findings commitment history sequence or scope differs.')
        previous=item['entry_sha256']
    require(F._time(context['prepared_at'])>=F._time(entries[-1]['entry']['recorded_at']),
        'Preparation clock precedes recorded findings.')
    epoch=dict(salt=salt.hex(),ledger_id=first['ledger_id'],officer_uid=first['officer_uid'])
    batch=keys.handle('FINDINGS_PUBLICATION',epoch)
    public_entries=[]
    for item in entries:
        handle=keys.handle('FINDINGS_ENTRY_HANDLE',dict(epoch=epoch,entry_sha256=item['entry_sha256']))
        commitment=keys.commit('FINDINGS_ENTRY_CONTENT',dict(epoch=epoch,publication_id=handle,context=context,entry=item))
        public_entries.append(dict(publication_id=handle,commitment=commitment))
    public_entries.sort(key=lambda e:e['publication_id'])
    history_commitment=keys.commit('FINDINGS_HISTORY_CONTENT',dict(epoch=epoch,context=context,history=history))
    publication_commitment=keys.commit('FINDINGS_PUBLICATION_CONTENT',dict(epoch=epoch,context=context,
        publication_id=batch,history_commitment=history_commitment,entries=public_entries))
    public=dict(policy=POLICY,commitment_version=1,key_version=keys.version,publication_id=batch,
        entries=public_entries,history_commitment=history_commitment,publication_commitment=publication_commitment)
    public['merkle_root']=merkle_root(_leaves(public));validate_public(public)
    private=dict(policy=POLICY,key_version=keys.version,salt=salt.hex(),context=deepcopy(context),
        history=deepcopy(history),public=deepcopy(public))
    return public,private


def inclusion_proof(public,publication_id):
    validate_public(public);leaves=_leaves(public)
    indices=[i for i,leaf in enumerate(leaves) if leaf['publication_id']==publication_id]
    require(len(indices)==1,'Publication handle outside findings tree.')
    index=indices[0];position=index;siblings=[]
    nodes=[sha256(b'\x00'+encoded(leaf)).digest() for leaf in leaves]
    while len(nodes)>1:
        if len(nodes)%2:nodes.append(nodes[-1])
        side='LEFT' if position%2 else 'RIGHT'
        siblings.append(dict(side=side,sha256=nodes[position-1 if position%2 else position+1].hex()))
        nodes=[sha256(b'\x01'+nodes[i]+nodes[i+1]).digest() for i in range(0,len(nodes),2)];position//=2
    return dict(policy=PROOF_POLICY,index=index,leaf_count=len(leaves),leaf=deepcopy(leaves[index]),siblings=siblings)


def verify_inclusion(public,proof):
    validate_public(public);leaves=_leaves(public)
    require(type(proof) is dict and set(proof)=={'policy','index','leaf_count','leaf','siblings'} and
        proof['policy']==PROOF_POLICY and type(proof['index']) is int and 0<=proof['index']<len(leaves) and
        type(proof['leaf_count']) is int and proof['leaf_count']==len(leaves) and
        proof['leaf']==leaves[proof['index']] and type(proof['siblings']) is list,'Findings proof scope differs.')
    node=sha256(b'\x00'+encoded(proof['leaf'])).digest();position=proof['index'];count=len(leaves);level=0
    while count>1:
        require(level<len(proof['siblings']),'Incomplete findings proof.')
        sibling=proof['siblings'][level];side='LEFT' if position%2 else 'RIGHT'
        require(type(sibling) is dict and set(sibling)=={'side','sha256'} and sibling['side']==side,
            'Findings proof direction differs.')
        F._sha(sibling['sha256']);other=bytes.fromhex(sibling['sha256'])
        if count%2 and position==count-1:require(other==node,'Odd Merkle node duplication differs.')
        node=sha256(b'\x01'+(other+node if side=='LEFT' else node+other)).digest()
        position//=2;count=(count+1)//2;level+=1
    require(level==len(proof['siblings']) and node.hex()==public['merkle_root'],'Findings inclusion proof differs.')
    return True


def _binding(public):
    return dict(artifact='PROTECTED_FINDINGS_COMMITMENTS',policy=POLICY,public_sha256=digest(public))


def _read(directory,repo,crypto,backup,expected_sha=None):
    root=_root(directory,repo);path=root/PRIVATE_NAME
    require(not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
        path.stat().st_mode&0o077==0,'Private findings commitment artifact required.')
    data=path.read_bytes();sha=sha256(data).hexdigest()
    if expected_sha is not None:F._sha(expected_sha);require(sha==expected_sha,'Approved commitment artifact pin differs.')
    envelope=F._json(data);binding=envelope['binding'];private=open_artifact(crypto,envelope,binding)
    require(open_artifact(backup,envelope,binding)==private and type(private) is dict and set(private)==PRIVATE_FIELDS and
        private['policy']==POLICY and private['key_version']==KEY_VERSION and binding==_binding(private['public']),
        'Findings commitment dual-key recovery or binding differs.')
    return sha,private


def verify_prepared(directory,repo,keys,backup_keys,crypto,backup,*,expected_private_sha256):
    """Verify an externally pinned saved artifact; does not claim latestness/anchoring."""
    require(_key_pin(keys)==_key_pin(backup_keys),'Findings commitment key recovery differs.')
    sha,private=_read(directory,repo,crypto,backup,expected_private_sha256)
    public,regenerated=generate(private['history'],keys,salt=bytes.fromhex(private['salt']),context=private['context'])
    require(private==regenerated,'Saved findings content commitment differs.')
    root=_root(directory,repo);path=root/PUBLIC_NAME
    require(not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
        path.stat().st_mode&0o077==0 and F._json(path.read_bytes())==public,'Saved findings public payload differs.')
    return dict(policy=POLICY,status='VERIFIED_SAVED',public_sha256=digest(public),private_artifact_sha256=sha,
        latest_history_checked=False,findings_anchored=False,accepted_state=None)


def _publish_public(path,public,check):
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.findings-public-',delete=False) as stream:
            temporary=Path(stream.name);os.fchmod(stream.fileno(),0o600)
            stream.write((canonical(public)+'\n').encode());stream.flush();os.fsync(stream.fileno())
        check();os.link(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temporary is not None:temporary.unlink(missing_ok=True)


def prepare(args,repo,revision,findings,*,key_file,backup_key_file,directory):
    """Operational backend: original replay/readiness and mTLS witness are mandatory."""
    require(type(findings) is W.WitnessedFindingsRegistry and findings.fixture_transport is False,
        'Operational findings mutual-TLS witness required.')
    findings._config()
    from app.identity.generate_protected_commitments import load_keys as original_loader
    from app.identity.algorithm_snapshot import load_verified_snapshot
    original=original_loader(args.commitment_key_file,args.backup_commitment_key_file,repo)
    snapshot=load_verified_snapshot(args,repo,revision)
    again=original_loader(args.commitment_key_file,args.backup_commitment_key_file,repo)
    require(original.version==again.version and original.content==again.content and original.publication==again.publication,
        'Original commitment keys changed during replay.')
    keys,backup_keys=load_keys(key_file,backup_key_file,repo)
    return prepare_loaded(snapshot,repo,findings,keys,backup_keys,original,directory=directory)


def prepare_loaded(snapshot,repo,findings,keys,backup_keys,original_keys,*,directory):
    """Internal full-loader boundary; configured objects and fixtures are not user APIs."""
    require(type(findings) is W.WitnessedFindingsRegistry,'Configured witnessed findings required.')
    journal=findings.registry.journal;repo=Path(repo).expanduser().resolve()
    require(journal.repo==repo,'Findings commitment repository differs.')
    require(journal.officer_uid in {b['officer_uid'] for b in snapshot['manifest']['bundles']},
        'Findings subject outside original anchored officer universe.')
    root=_root(directory,repo)
    for store in (journal.root,findings.registry.root):
        _root(store,repo)
        require(not root.is_relative_to(store) and not store.is_relative_to(root),'Commitment output must be separate from findings stores.')
    require({p.name for p in root.iterdir()}<=set((PRIVATE_NAME,PUBLIC_NAME)),
        'Dedicated commitment directory contains unexpected artifacts; inspect interrupted staging.')
    for name in (PRIVATE_NAME,PUBLIC_NAME):require(not (root/name).is_symlink(),'Commitment artifact symlink refused.')
    _separate(keys,backup_keys,original_keys,findings,snapshot)
    permit=AlgorithmPermit(snapshot);permit.check(snapshot)
    history=findings.select();require(history['entries'],'No findings available for commitment.')
    key_pin=_key_pin(keys);original_pin=digest([original_keys.version,original_keys.content.hex(),original_keys.publication.hex()]);scope=deepcopy(findings.scope);pins=deepcopy(findings.registry.key_pins)
    source=digest(dict(manifest=snapshot['manifest'],catalog=snapshot['catalog'],bindings=snapshot['bindings']))
    context=dict(source_context=deepcopy(snapshot['context']),original_publication_sha256=digest(snapshot['public']),
        generator_revision=snapshot['context']['code_revision'],prepared_at=J._now().astimezone(timezone.utc).isoformat(),key_pins=pins)
    def check():
        permit.check(snapshot);_root(root,repo);_separate(keys,backup_keys,original_keys,findings,snapshot)
        require(_key_pin(keys)==key_pin and digest([original_keys.version,original_keys.content.hex(),original_keys.publication.hex()])==original_pin and
            J._now().astimezone(timezone.utc)>=F._time(context['prepared_at']) and findings.scope==scope and findings.registry.key_pins==pins and
            snapshot['context']==context['source_context'] and digest(snapshot['public'])==context['original_publication_sha256'] and
            digest(dict(manifest=snapshot['manifest'],catalog=snapshot['catalog'],bindings=snapshot['bindings']))==source,
            'Findings commitment evidence, context or configuration changed.')
        require(findings.select()==history,'Latest witnessed findings changed during preparation.')
        permit.check(snapshot)
    if (root/PRIVATE_NAME).exists():
        sha,private=_read(root,repo,snapshot['crypto'],snapshot['backup'])
        expected=deepcopy(context);expected['prepared_at']=private['context']['prepared_at']
        require(private['history']==history and private['context']==expected,'Saved preparation is not this current witnessed snapshot.')
        public,regenerated=generate(history,keys,salt=bytes.fromhex(private['salt']),context=private['context'])
        require(private==regenerated,'Saved commitment preparation differs.');context=expected
    else:
        require(not (root/PUBLIC_NAME).exists(),'Orphaned public payload cannot establish a preparation.')
        public,private=generate(history,keys,salt=os.urandom(32),context=context)
        sha=J._publish(root/PRIVATE_NAME,private,snapshot['crypto'],snapshot['backup'],_binding(public),check)
    check()
    if not (root/PUBLIC_NAME).exists():_publish_public(root/PUBLIC_NAME,public,check)
    result=verify_prepared(root,repo,keys,backup_keys,snapshot['crypto'],snapshot['backup'],expected_private_sha256=sha)
    check();result.update(status='PREPARED',latest_history_checked=True)
    return result
