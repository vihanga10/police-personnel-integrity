"""Authenticate once, then recheck unchanged permit and publication before work.

The Merkle plan is validated by the existing gate on entry. Repeated checks
authenticate both recovery keys and hash the complete publication. An identical
publication digest retains that validation without rebuilding 6,597 leaves for
each officer. This never extends the permit deadline or refreshes live evidence.
"""
from datetime import datetime, timezone, timedelta
from app.identity.audit_gate import require_audit_permit, binding
from app.identity.evidence_bundle_v2 import open_artifact, canonical
from app.identity.protected_commitment import digest
from app.identity.historical_reconstruction import require


class AlgorithmPermit:
    def __init__(self, snapshot):
        permit=require_audit_permit(snapshot['envelope'],snapshot['crypto'],snapshot['backup'],
            snapshot['public'],snapshot['context'])
        # Strings do not share mutable references with the input snapshot.
        self._permit=canonical(permit)
        self._publication_digest=digest(snapshot['public'])

    def check(self, snapshot, *, now=None):
        now=now or datetime.now(timezone.utc)
        envelope=snapshot['envelope'];context=snapshot['context']
        primary=open_artifact(snapshot['crypto'],envelope,binding(context))
        backup=open_artifact(snapshot['backup'],envelope,binding(context))
        require(canonical(primary)==canonical(backup)==self._permit,
            'Algorithm permit or recovery differs.')
        require(digest(snapshot['public'])==self._publication_digest,
            'Algorithm publication changed.')
        checked,issued,expires=(datetime.fromisoformat(primary[k])
            for k in ('checked_at','issued_at','expires_at'))
        require(checked<=issued<=now<expires and expires==checked+timedelta(seconds=600),
            'Audit permit expired or time differs.')
        return primary
