"""Protected findings-to-Fabric-to-local-public backend coordination.

Trusted backend objects only. No API route, source-loader override, automatic
approval, transaction replacement, provisioning or live public transport.
Restart reconstructs this coordinator with the original approved selection and
the workers' witnessed recovery directories; RECONCILE never executes writes.
"""
from copy import deepcopy
import re
from app.identity import findings_backend_gate as G
from app.identity import findings_backend_service as F
from app.identity import findings_public_backend_gate as P
from app.identity import findings_public_backend_service as U
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest

POLICY = 'PROTECTED_FINDINGS_BACKEND_PIPELINE_V1'
FABRIC_FIELDS = P.FABRIC_OPTIONS - {'approval','trusted_keys'}
PUBLIC_FIELDS = frozenset(('node_binary','network_config_file','witness_config_file',
    'witness_config_sha256','recovery_directory','recovery_key_file','timeout',
    'runtime_config_file','runtime_config_sha256'))


def _trust(keys):
    require(type(keys) is dict and keys and all(type(k) is str and k and
        type(v) is bytes and len(v) == 32 for k,v in keys.items()),
        'Configured Ed25519 pipeline trust required.')
    return deepcopy(keys)


class FindingsBackendPipeline:
    """Connect existing protected services without trusting submitted receipts.

    Fabric and public approvals are separate, domain-bound signed grants. Public
    preparation requires a fresh read-only Fabric approval after Fabric commit.
    No callback can approve a source or replace a chain adapter in this entry.
    """
    def __init__(self,source_gate,read_gate,*,fabric_options,public_options,
            fabric_trusted_keys,public_trusted_keys,public_config,public_destination):
        require(type(source_gate) is G.FindingsBackendGate and type(read_gate) is G.FindingsBackendGate and
            source_gate.mode in ('EXECUTE','RECONCILE') and read_gate.mode == 'RECONCILE',
            'Typed execution and read-only full-source gates required.')
        require(source_gate.repo == read_gate.repo and source_gate.revision == read_gate.revision and
            source_gate.findings is read_gate.findings and source_gate.selection == read_gate.selection,
            'Pipeline source/history selections differ.')
        require(type(fabric_options) is dict and set(fabric_options) == FABRIC_FIELDS and
            type(public_options) is dict and set(public_options) == PUBLIC_FIELDS and
            public_options['runtime_config_file'] is not None and public_options['runtime_config_sha256'] is not None,
            'Exact configured pipeline service options required.')
        self.source,self.read = source_gate,read_gate
        self.mode = source_gate.mode
        self._mode = self.mode
        self.fabric_options,self.public_options = deepcopy(fabric_options),deepcopy(public_options)
        self.fabric_trusted_keys,self.public_trusted_keys = _trust(fabric_trusted_keys),_trust(public_trusted_keys)
        self.public_config,self.public_destination = P.network_config(public_config),deepcopy(public_destination)
        self._objects = (source_gate,read_gate)
        self._source = source_gate.selection
        self._configuration = deepcopy((self.fabric_options,self.public_options,self.fabric_trusted_keys,
            self.public_trusted_keys,self.public_config,self.public_destination))
        self._check()

    def _check(self):
        require(self.source is self._objects[0] and self.read is self._objects[1] and
            self.mode == self._mode and self.source.mode == self.mode and self.read.mode == 'RECONCILE' and
            self.source.findings is self.read.findings and self.source.repo == self.read.repo and
            self.source.revision == self.read.revision and
            (self.fabric_options,self.public_options,self.fabric_trusted_keys,self.public_trusted_keys,
                self.public_config,self.public_destination) == self._configuration,
            'Pipeline configuration changed.')
        require(self.source.check('ENTRY',self._source,self.mode) == self._source and
            self.read.check('ENTRY',self._source,'RECONCILE') == self._source,
            'Verified pipeline source changed.')

    def fabric_selection(self):
        """Return an opaque approval selection derived from verified findings."""
        self._check()
        return deepcopy(self._source)

    def run_fabric(self,approval):
        """EXECUTE or read-only RECONCILE, fixed by the source gate's mode."""
        self._check()
        G.verify_approval(approval,self.fabric_trusted_keys,self._source,self.mode)
        result = F.run_fabric(self.source,approval=deepcopy(approval),
            trusted_keys=deepcopy(self.fabric_trusted_keys),**deepcopy(self.fabric_options))
        self._check()
        # Reuse the strict receipt verifier's exact schema, not a status label.
        r = result.get('receipt',{})
        require(result.get('backend_gate') == 'FULL_REPLAY_AND_WITNESSED_FINDINGS' and
            result.get('status') == 'FABRIC_COMMIT_VERIFIED' and result.get('mode') == self.mode and
            type(r) is dict and set(r) == {'status','destination','payload','transaction_id','verification'} and
            r['status'] == 'FINAL' and r['destination'] == self._source['destination'] and
            r['payload'] == self._source['payload'], 'Pipeline Fabric result differs.')
        v = r['verification']
        require(type(v) is dict and set(v) == {'validation_code','organizations','block_sha256'} and
            v['validation_code'] == 'VALID' and v['organizations'] == ['Org1MSP','Org2MSP'] and
            all(type(x) is str and re.fullmatch('[0-9a-f]{64}',x) for x in (r['transaction_id'],v['block_sha256'])),
            'Original VALID Fabric receipt required.')
        return deepcopy(result)

    def _public_gate(self,fabric_read_approval):
        self._check()
        G.verify_approval(fabric_read_approval,self.fabric_trusted_keys,self._source,'RECONCILE')
        verifier = P.FabricReceiptVerifier(self.read,approval=deepcopy(fabric_read_approval),
            trusted_keys=deepcopy(self.fabric_trusted_keys),**deepcopy(self.fabric_options))
        gate = P.FindingsPublicBackendGate(self.source,verifier,
            config=deepcopy(self.public_config),destination=deepcopy(self.public_destination))
        self._check()
        return gate

    def public_selection(self,fabric_read_approval):
        """Observe the original Fabric transaction, then return public scope.

        This does not sign, submit, repair recovery state or accept a caller's
        receipt. The original Fabric receipt is derived by the read-only service.
        """
        return self._public_gate(fabric_read_approval).selection

    def run_public(self,*,fabric_read_approval,public_approval,expected_selection):
        """Execute the approved original public plan, or reconcile read-only.

        Pending/uncertain operations are never automatically rerun as EXECUTE.
        Reconstruct with RECONCILE source gates and fresh signed approvals.
        """
        gate = self._public_gate(fabric_read_approval)
        require(type(expected_selection) is dict and expected_selection == gate.selection,
            'Original approved public pipeline selection differs.')
        P.verify_approval(public_approval,self.public_trusted_keys,gate.selection,self.mode)
        result = U.run_public(gate,approval=deepcopy(public_approval),
            trusted_keys=deepcopy(self.public_trusted_keys),**deepcopy(self.public_options))
        self._check()
        # Re-observe Fabric AFTER the public worker and bind it to the receipt
        # used at the public boundaries. The public service independently checks
        # its exact payload, signed transaction and final/PENDING receipt schema.
        require(gate.check('RETURN',expected_selection,self.mode) == expected_selection,
            'Pipeline source/Fabric changed before return.')
        require(result.get('backend_gate') == 'FULL_SOURCE_AND_FRESH_FABRIC' and
            result.get('status') in ('ISOLATED_PUBLIC_VERIFIED','PENDING') and
            result.get('mode') == self.mode and result.get('live_research_ready') is False and
            result.get('public_finality_simulated') is True and
            result.get('provider_independence_verified') is False and
            result.get('both_chains_anchored') is False,
            'Isolated public pipeline result required.')
        return dict(policy=POLICY,status='ISOLATED_PIPELINE_VERIFIED' if
            result['status'] == 'ISOLATED_PUBLIC_VERIFIED' else 'PENDING',mode=self.mode,
            workflow_sha256=digest(dict(policy=POLICY,fabric=self._source,public=expected_selection)),
            source_selection=deepcopy(self._source),public_selection=deepcopy(expected_selection),
            fabric_receipt=deepcopy(expected_selection['fabric_receipt']),public_result=deepcopy(result),
            full_source_gate_required=True,public_finality_simulated=True,
            provider_independence_verified=False,independent_witness_deployment_verified=False,
            both_chains_anchored=False,live_research_ready=False)
