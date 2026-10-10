"""Independent latest-tip checks for findings, using the existing witness protocol.

Trusted configured backend only. No service deployment, protected-producer
readiness waiver, cached-tip fallback or automatic enrollment is provided.
"""
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
from app.identity import findings_tip_registry as R
from app.identity import encrypted_findings_journal as F
from app.identity import observed_recording_journal as J
from app.identity import recording_tip_witness as W
from app.identity.witness_secure_transport import HTTPSWitnessTransport
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest

POLICY='WITNESSED_FINDINGS_TIP_REGISTRY_V1'
SCOPE_POLICY='FINDINGS_WITNESS_SCOPE_V1'


def findings_scope_anchor(registry_id,ledger_id):
    """Typed nonpersonal scope hash shared by backend and witness provisioning."""
    F._uuid(registry_id);F._uuid(ledger_id)
    return digest(dict(policy=SCOPE_POLICY,registry_id=registry_id,ledger_id=ledger_id))


class WitnessedFindingsRegistry:
    """Fresh witness selection and publication; test transports require explicit opt-in.

    The witness service must be independently administered and protected against
    rollback itself. This adapter cannot prove independent deployment/restore
    controls or revalidate original research readiness from an old receipt.
    """
    def __init__(self,registry,client,*,fixture_transport=False):
        require(type(registry) is R.FindingsTipRegistry and type(client) is W.WitnessClient and
            type(fixture_transport) is bool,'Configured findings registry and witness client required.')
        self.registry=registry;self.client=client;self.fixture_transport=fixture_transport
        self.scope=dict(client.scope)
        require(self.scope['registry_id']==registry.registry_id and
            self.scope['journal_anchor']==findings_scope_anchor(registry.registry_id,registry.journal.ledger_id),
            'Findings witness scope differs.')
        require(client.writer_keys==registry.registry_keys and client.key_id==registry.key_id,
            'Findings witness writer pins differ.')
        authorities=set(registry.registry_keys.values())|set(registry.recovery_keys.values())|\
            set(registry.journal.writer_keys.values())|set(registry.journal.reviewer_keys.values())
        require(not authorities&set(client.witness_keys.values()),'Findings witness authority must have separate keys.')
        self.key_pins=(W._key_digest(client.writer_keys),W._key_digest(client.witness_keys))
        self._config()

    def _config(self):
        registry=self.registry;registry._config()
        require(self.client.scope==self.scope and
            self.scope['registry_id']==registry.registry_id and
            self.scope['journal_anchor']==findings_scope_anchor(registry.registry_id,registry.journal.ledger_id) and
            self.client.writer_keys==registry.registry_keys and self.client.key_id==registry.key_id and
            (W._key_digest(self.client.writer_keys),W._key_digest(self.client.witness_keys))==self.key_pins,
            'Findings witness scope or key pins changed.')
        if not self.fixture_transport:
            transport=self.client.exchange
            require(type(transport) is HTTPSWitnessTransport,'Configured findings mutual-TLS transport required.')
            require(Path(transport.repo).expanduser().resolve()==registry.journal.repo and
                all(transport.profile[k]==self.scope[k] for k in W.SCOPE) and
                transport.writer_key_id==self.client.key_id and
                transport.profile['writer_keys_sha256']==self.key_pins[0] and
                transport.profile['witness_keys_sha256']==self.key_pins[1],
                'Findings secure transport scope or key pins differ.')

    def _wire(self,tip):
        R._tip(tip,'registry_id',self.registry.registry_id)
        return None if tip['sequence']==0 else dict(sequence=tip['sequence'],sha256=tip['entry_sha256'])

    def _tip(self,wire):
        W.R._pin(wire)
        return self.registry.empty_tip() if wire is None else self.registry._tip(wire['sequence'],wire['sha256'])

    def _head(self):
        self._config();tip=self._tip(self.client.head());self._config();return tip

    def _selected(self,tip):
        entries=self.registry._entries(tip);history=self.registry._history(entries)
        return dict(policy=POLICY,registry_tip=deepcopy(tip),journal_tip=self.registry._journal_tip(entries),
            entries=deepcopy(history),witness_scope=deepcopy(self.scope),
            accepted_state=None,findings_anchored=False)

    def select(self):
        tip=self._head()
        with self.registry._locked(),self.registry.journal._lock():
            result=self._selected(tip)
            require(self._head()==tip,'Findings witness advanced during selection.')
            require(self._selected(tip)==result,'Findings history changed during selection.')
            return result  # Sensitive plaintext: authorized backend only.

    def _acknowledge(self,expected,proposed):
        require(proposed['sequence']==expected['sequence']+1,'Findings witness cannot skip registry entries.')
        with self.registry._locked(),self.registry.journal._lock():
            self._config();entries=self.registry._entries(proposed);self.registry._history(entries)
            require(entries[-1]['value']['previous_sha256']==expected['entry_sha256'],
                'Published findings registry does not preserve witness prefix.')
            if expected['sequence']:
                prefix=self.registry.root/f"entry-{expected['sequence']:08d}.encrypted.json"
                require(sha256(prefix.read_bytes()).hexdigest()==expected['entry_sha256'],
                    'Findings witness prefix hash differs.')
            # Reflush both local stores before acknowledging a durable remote tip.
            for root in (self.registry.journal.root,self.registry.root):
                fd=os.open(root,os.O_RDONLY)
                try:os.fsync(fd)
                finally:os.close(fd)
            self.client.advance(self._wire(expected),self._wire(proposed))
            require(self._head()==proposed,'Findings witness advanced before acknowledgment completed.')
            self._selected(proposed);return deepcopy(proposed)

    def _finish(self,expected,result):
        proposed=result['registry_tip']
        if proposed==expected:
            require(self.select()['registry_tip']==expected,'Findings witness advanced during retry.')
            status='ALREADY_WITNESSED'
        else:
            proposed=self._acknowledge(expected,proposed);status='WITNESSED'
        return dict(policy=POLICY,status=status,registry_tip=proposed,journal_tip=result['journal_tip'],
            accepted_state=None,findings_anchored=False)

    def append_receipt(self,**kwargs):
        expected=self._head()
        result=self.registry.append_receipt(expected_registry_tip=expected,**kwargs)
        return self._finish(expected,result)

    def append_review(self,*,intent):
        expected=self._head()
        result=self.registry.append_review(expected_registry_tip=expected,intent=intent)
        return self._finish(expected,result)

    def authorize_recovery(self,**kwargs):
        """Trusted signer helper binds the current fresh witness predecessor."""
        expected=self._head()
        receipt=self.registry.authorize_recovery(expected_registry_tip=expected,**kwargs)
        require(self._head()==expected,'Findings witness advanced during recovery issuance.')
        return receipt

    def recover(self,authorization):
        authorization=deepcopy(authorization);expected=self._head()
        # Verify signature and expiry before using any authorization-supplied pins.
        auth=self.registry._authorization(authorization,J._now())
        require(auth['registry_tip']==expected,'Recovery predecessor differs from fresh findings witness.')
        result=self.registry.recover(authorization)
        return self._finish(expected,result)
