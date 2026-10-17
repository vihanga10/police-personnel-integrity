"""Displayed current personnel state with a stated basis for every changed field.

Starts from the signed source service record and applies only accepted,
currently effective uploaded evidence. Scheduled (future-effective) accepted
changes and pending rows are reported separately. Source rows never change.
"""
from app.identity.service_values import RANKS

POLICY = 'DISPLAYED_CURRENT_STATE_V1'
POSTING = {'current_station_code': 'to_station_code', 'current_station': 'to_station_name',
           'current_unit_type': 'to_unit_type', 'current_unit_name': 'to_unit_name',
           'current_division': 'to_division', 'current_province': 'to_province'}


def current_state(baseline, promotion=None, datasets=None):
    fields, basis = dict(baseline), {}
    projection = (datasets or {}).get('projection') or {}

    def apply(name, value, source, accepted):
        if value is None or value == '':
            return
        fields[name] = value
        basis[name] = {'basis': source, 'acceptance_reference': accepted['acceptance_reference'],
                       'effective_on': accepted['effective_on']}
    snapshot = projection.get('service_snapshot')
    if snapshot:
        for name, value in snapshot['fields'].items():
            if name not in ('service_id', 'officer_nic_no'):
                apply(name, value.strip(), 'ACCEPTED_SERVICE_SNAPSHOT', snapshot)
    # Rank: the latest effective accepted promotion or demotion; ties favour the demotion.
    candidates = []
    accepted = (promotion or {}).get('accepted_promotion')
    if accepted:
        candidates.append((accepted['effective_on'], 0, accepted['to_rank'], 'ACCEPTED_PROMOTION_EFFECTIVE_NOW', accepted))
    demotion = projection.get('demotion')
    if demotion:
        candidates.append((demotion['effective_on'], 1, demotion['floor_rank'], 'ACCEPTED_DEMOTION_EFFECTIVE_NOW', demotion))
    if candidates:
        _, _, label, source, item = max(candidates, key=lambda c: (c[0], c[1]))
        apply('current_rank', label, source, item)
    posting = projection.get('posting')
    if posting:
        for name, key in POSTING.items():
            apply(name, posting[key], 'ACCEPTED_TRANSFER_EFFECTIVE_NOW', posting)
    rank_code = RANKS.get(fields.get('current_rank', '').strip())
    return {'policy': POLICY, 'fields': fields, 'basis': basis, 'rank_code': rank_code,
            'police_numbers': projection.get('police_numbers', []),
            'active_restrictions': projection.get('active_restrictions', []),
            'scheduled_effects': (datasets or {}).get('scheduled_effects', []),
            'pending_rows': (datasets or {}).get('pending_rows', 0) + (promotion or {}).get('pending_promotions', 0),
            'changed': bool(basis), 'source_records_preserved': True}
