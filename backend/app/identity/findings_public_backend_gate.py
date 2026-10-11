"""Full source/Fabric gate for the fixture-only public bridge; no live RPC."""
from copy import deepcopy
from datetime import datetime,timezone
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit
import base64
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.identity import findings_backend_gate as G
from app.identity import findings_backend_service as S
from app.identity.controlled_findings_anchoring import destinations
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest,encoded

POLICY='PROTECTED_FINDINGS_PUBLIC_FIXTURE_V1'
ACTIONS=frozenset(('ENTRY','INTENT','PREFLIGHT','RUNTIME','SIGN','PLAN','ATTEMPT','SUBMIT','ACK','OBSERVE','VERIFIED','FINAL','RETURN'))
FABRIC_OPTIONS=frozenset(('approval','trusted_keys','node_binary','gateway_config_file','witness_config_file',
    'witness_config_sha256','recovery_directory','recovery_key_file','timeout'))


def verify_approval(grant,keys,selection,mode):
    require(type(grant) is dict and set(grant)=={'body','signature'},'Exact public approval required.')
    b=grant['body']
    require(type(b) is dict and set(b)=={'policy','key_id','mode','issued_at','expires_at','selection'} and
        b['policy']==POLICY and b['mode']==mode and mode in ('EXECUTE','RECONCILE') and b['selection']==selection,
        'Public approval scope differs.')
    require(type(b['key_id']) is str and b['key_id'] in keys,'Trusted public approver required.')
    key=keys[b['key_id']];require(type(key) is bytes and len(key)==32,'Pinned public approver required.')
    require(type(grant['signature']) is str,'Canonical public signature required.')
    sig=base64.b64decode(grant['signature'],validate=True)
    require(len(sig)==64 and base64.b64encode(sig).decode()==grant['signature'],'Canonical public signature required.')
    Ed25519PublicKey.from_public_bytes(key).verify(sig,encoded(b))
    def date(v):
        require(type(v) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z',v),'Canonical UTC approval required.')
        t=datetime.fromisoformat(v.replace('Z','+00:00'))
        require(t.isoformat(timespec='milliseconds').replace('+00:00','Z')==v,'Canonical approval date required.')
        return t
    start,end=date(b['issued_at']),date(b['expires_at'])
    require(start<=datetime.now(timezone.utc)<end and 0<(end-start).total_seconds()<=600,'Fresh bounded public approval required.')


def network_config(c):
    require(type(c) is dict and set(c)=={'policy','rpc_urls','max_fee_gwei','priority_fee_gwei','max_total_fee_eth','confirmations'} and
        c['policy']=='FINDINGS_PUBLIC_NETWORK_FIXTURE_V1','Fixture-only public configuration required.')
    require(type(c['rpc_urls']) is list and len(c['rpc_urls'])==2,'Two fixture endpoints required.')
    hosts=[]
    for url in c['rpc_urls']:
        require(type(url) is str,'Fixture endpoint required.')
        u=urlsplit(url)
        require(u.scheme=='https' and u.hostname and u.hostname.endswith('.invalid') and
            not u.username and not u.password and not u.query and not u.fragment,'Live public endpoints disabled.')
        hosts.append(u.hostname)
    require(hosts[0]!=hosts[1],'Distinct fixture provider hosts required.')
    require(type(c['confirmations']) is int and 12<=c['confirmations']<=128,'Bounded confirmations required.')
    for k in ('max_fee_gwei','priority_fee_gwei','max_total_fee_eth'):
        require(type(c[k]) is str and re.fullmatch(r'\d+(\.\d{1,9})?',c[k]),'Bounded decimal fees required.')
    fee,tip,budget=(Decimal(c[k]) for k in ('max_fee_gwei','priority_fee_gwei','max_total_fee_eth'))
    require(0<fee<=20 and 0<tip<=fee and 0<budget<=Decimal('0.1'),'Fee bounds exceeded.')
    return deepcopy(c)


class FabricReceiptVerifier:
    """Configured original read-only service; no submit or caller observer override."""
    def __init__(self,gate,**service_options):
        require(type(gate) is G.FindingsBackendGate and gate.mode=='RECONCILE','Read-only Fabric backend gate required.')
        require(set(service_options)==FABRIC_OPTIONS,'Exact configured Fabric service options required.')
        self.gate,self.options=gate,deepcopy(service_options)
        self._gate,self._options=gate,deepcopy(service_options)
        self._selection=gate.selection;self._receipt=None
    @property
    def selection(self):return deepcopy(self._selection)
    def verify(self):
        require(self.gate is self._gate and self.options==self._options and type(self.gate) is G.FindingsBackendGate and self.gate.mode=='RECONCILE' and
            self.gate.selection==self._selection,'Fabric verifier configuration changed.')
        result=S.run_fabric(self.gate,**deepcopy(self.options))
        require(result.get('backend_gate')=='FULL_REPLAY_AND_WITNESSED_FINDINGS' and
            result.get('mode')=='RECONCILE' and result.get('status')=='FABRIC_COMMIT_VERIFIED',
            'Fresh verified read-only Fabric result required.')
        r=result['receipt'];v=r.get('verification',{})
        require(set(r)=={'status','destination','payload','transaction_id','verification'} and
            set(v)=={'validation_code','organizations','block_sha256'} and r['status']=='FINAL' and
            r['destination']==self._selection['destination'] and r['payload']==self._selection['payload'] and
            v['validation_code']=='VALID' and v['organizations']==['Org1MSP','Org2MSP'],
            'Original two-organization Fabric receipt differs.')
        for value in (r['transaction_id'],v['block_sha256']):
            require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value),'Fabric receipt digest differs.')
        if self._receipt is None:self._receipt=deepcopy(r)
        require(r==self._receipt,'Original Fabric receipt changed.')
        return deepcopy(r)


class FindingsPublicBackendGate:
    """Backend-configured objects only; replays source and Fabric at each action."""
    def __init__(self,source_gate,fabric_verifier,*,config,destination):
        require(type(source_gate) is G.FindingsBackendGate and source_gate.mode in ('EXECUTE','RECONCILE'),
            'Typed full-source backend gate required.')
        require(type(fabric_verifier) is FabricReceiptVerifier,'Configured Fabric receipt verifier required.')
        self.source,self.fabric=source_gate,fabric_verifier
        self._source,self._fabric=source_gate,fabric_verifier
        self.repo,self.revision,self.mode=source_gate.repo,source_gate.revision,source_gate.mode
        self.directory,self.findings=source_gate.directory,source_gate.findings
        self.config=network_config(deepcopy(config));self.destination=deepcopy(destination)
        self._selection=None;self._selection=self._verify()
    @property
    def selection(self):return deepcopy(self._selection)
    def _verify(self):
        require(self.source is self._source and self.fabric is self._fabric and type(self.source) is G.FindingsBackendGate and type(self.fabric) is FabricReceiptVerifier and
            self.source.repo==self.repo and self.source.revision==self.revision and self.source.mode==self.mode,
            'Public source configuration changed.')
        source=self.source.check('ENTRY',self.source.selection,self.mode)
        require(source==self.fabric.selection and self.fabric.gate.repo==self.repo and
            self.fabric.gate.revision==self.revision,'Public/Fabric source selection differs.')
        receipt=self.fabric.verify()
        # Fabric observation can take time. Recheck latest/prefix source policy
        # afterward too, before approving the public boundary.
        require(self.source.check('ENTRY',source,self.mode)==source,'Source changed during Fabric observation.')
        p=source['payload']
        destinations({'fabric':source['destination'],'public':self.destination})
        cfg=network_config(self.config)
        selected=dict(private_sha256=source['private_sha256'],public_sha256=source['public_sha256'],
            history_sha256=source['history_sha256'],code_revision=source['code_revision'],network_config_sha256=digest(cfg),
            destination=deepcopy(self.destination),fabric_receipt=receipt,payload=dict(policy='FINDINGS_PUBLIC_ANCHOR_V1',
                namespace='findings-anchor-v1',publication_id=p['publication_id'],public_sha256=p['public_sha256'],
                merkle_root=p['merkle_root'],fabric_destination_sha256=digest(receipt['destination']),
                fabric_transaction_id=receipt['transaction_id'],fabric_receipt_sha256=digest(receipt)))
        if self._selection is not None:require(selected==self._selection,'Public backend selection changed.')
        return selected
    def check(self,action,selection,mode):
        require(action in ACTIONS and mode==self.mode and selection==self._selection,'Public backend guard scope differs.')
        return deepcopy(self._verify())
    def check_recovery_key(self,value):
        self.source.check_recovery_key(value)
        require(value!=Path(self.fabric.options['recovery_key_file']).read_bytes(),'Separate Fabric/public recovery keys required.')
