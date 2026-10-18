"""One officer's integrity story: original fingerprint, every upload batch, and a checkpoint chain.

Everything here is recomputed from retained, encrypted evidence at read time.
An inclusion check shows that a retained row's commitment belongs to a batch
root that was published on Fabric and Sepolia; it does not show the row is true.
The per-officer checkpoint chain is derived from those anchored batch roots; its
head is not itself a separate on-chain transaction.
"""
from app.intake.promotion_pipeline.core import digest
from app.intake.dataset_pipeline import merkle_proof as M
from app.intake.dataset_pipeline.registry import dataset

POLICY = 'OFFICER_INTEGRITY_VIEW_V1'
CHAIN_POLICY = 'OFFICER_CHECKPOINT_CHAIN_V1'


def original(store, officer):
    found = store.original_commitment(officer) if store is not None else None
    if found is None:
        return None
    entry, meta = found
    node = bytes.fromhex(entry['leaf_sha256'])
    recomputed = M.fold(node, entry['proof'])
    receipts = store.original_receipts()
    anchors = None
    if receipts is not None and receipts['merkle_root'] == meta['merkle_root']:
        chunk = entry['leaf_index'] // receipts['chunk_size']
        anchors = {'chunk': chunk, 'chunk_size': receipts['chunk_size'], 'fabric': receipts['fabric']['chunk-%03d' % chunk],
                   'sepolia': receipts['sepolia'][chunk + 1], 'fabric_begin': receipts['fabric']['batch'], 'fabric_seal': receipts['fabric']['seal'],
                   'sepolia_begin': receipts['sepolia'][0], 'sepolia_final': receipts['sepolia'][-1], 'transactions_per_chain': len(receipts['sepolia'])}
    return {'anchors': anchors, 'publication_id': entry['publication_id'], 'commitment': entry['commitment'], 'leaf_sha256': entry['leaf_sha256'],
            'leaf_index': entry['leaf_index'], 'proof_length': len(entry['proof']), 'recomputed_root': recomputed,
            'inclusion_verified': recomputed == meta['merkle_root'], **{k: meta[k] for k in meta if k != 'officers'},
            'officers_in_batch': meta['officers']}


def batch_entries(kind, intake, analysis, officer, reports):
    """Per batch: this officer's rows with recomputed inclusion in the published root."""
    entries = []
    for batch_id in sorted({r['batch_id'] for r in reports}, key=lambda b: min(r['analysis_recorded_at'] for r in reports if r['batch_id'] == b)):
        batch = intake.get(batch_id)
        payload, manifest = intake.publication(batch)
        leaves = manifest['rows']
        ready = [r for r in batch['rows'] if r['status'] == 'READY']
        nodes = [M.leaf_node(bytes.fromhex(v)) for v in leaves]
        recomputed_root = M.root(nodes)
        mine = [i for i, r in enumerate(ready) if officer in intake.row_officers(r)]
        mine_reports = [r for r in reports if r['batch_id'] == batch_id]
        sample = mine_reports[0]
        proofs = []
        for i in mine:
            path = M.proof(nodes, i)
            proofs.append({'row': ready[i]['row'], 'leaf_sha256': leaves[i], 'leaf_index': i, 'proof_length': len(path),
                           'included': M.fold(nodes[i], path) == payload['merkle_root']})
        publication = sample['publication']
        entries.append({'kind': kind, 'record_type': sample.get('dataset') or 'PROMOTIONS',
            'record_type_label': dataset(sample['dataset']).label if sample.get('dataset') else 'Promotions',
            'batch_id': batch_id, 'filename': batch['filename'], 'uploaded_at': batch['received_at'],
            'activated_at': sample['analysis_recorded_at'], 'activation_reference': sample['activation_reference'],
            'rows_for_officer': proofs, 'rows_in_batch': len(ready),
            'publication_id': payload['publication_id'], 'merkle_root': payload['merkle_root'],
            'recomputed_root': recomputed_root, 'root_matches_published': recomputed_root == payload['merkle_root'] == publication['merkle_root'],
            'all_rows_included': bool(proofs) and all(p['included'] for p in proofs),
            'fabric_transaction_id': publication['fabric_transaction_id'], 'public_transaction_id': publication['public_transaction_id'],
            'public_contract': publication['public_contract'], 'verified_at': publication['verification_observed_at']})
    return entries


def chain(start, uploads):
    previous = start or '0' * 64
    links = []
    for n, item in enumerate(sorted(uploads, key=lambda u: (u['activated_at'], u['batch_id'])), 1):
        link = digest({'policy': CHAIN_POLICY, 'previous': previous, 'batch_publication_id': item['publication_id'],
                       'merkle_root': item['merkle_root'], 'row_leaves': [p['leaf_sha256'] for p in item['rows_for_officer']],
                       'activation_reference': item['activation_reference'], 'fabric_transaction_id': item['fabric_transaction_id'],
                       'public_transaction_id': item['public_transaction_id']})
        links.append({'sequence': n, 'previous': previous, 'hash': link, 'batch_id': item['batch_id'],
                      'record_type_label': item['record_type_label'], 'activated_at': item['activated_at']})
        previous = link
    return {'policy': CHAIN_POLICY, 'genesis': start or '0' * 64, 'links': links, 'head': previous, 'length': len(links)}


def officer_integrity(service, officer):
    sources = []
    if getattr(service, 'promotion_analysis', None) is not None:
        sources.append(('PROMOTIONS', service.promotion_analysis.intake, service.promotion_analysis))
    if getattr(service, 'dataset_analysis', None) is not None:
        sources.append(('DATASET', service.dataset_analysis.intake, service.dataset_analysis))
    dataset_store = service.dataset_analysis.intake if getattr(service, 'dataset_analysis', None) is not None else None
    base = original(dataset_store, officer)
    uploads, errors = [], []
    for kind, intake, analysis in sources:
        try:
            reports = analysis.reports(officer)
            if reports:
                uploads += batch_entries(kind, intake, analysis, officer, reports)
        except Exception as error:
            # A batch that no longer recomputes to its published commitment must be visible, never hidden.
            errors.append(getattr(error, 'code', 'VERIFICATION_ERROR'))
    checkpoints = chain(base['leaf_sha256'] if base else None, uploads)
    everything_ok = not errors and all(u['root_matches_published'] and u['all_rows_included'] for u in uploads) and (base is None or base['inclusion_verified'])
    return {'policy': POLICY, 'original': base, 'original_available': base is not None,
            'uploads': sorted(uploads, key=lambda u: u['activated_at']), 'checkpoint_chain': checkpoints,
            'all_recomputed_checks_passed': everything_ok, 'verification_errors': sorted(set(errors)), 'basis': 'RECOMPUTED_FROM_RETAINED_ENCRYPTED_EVIDENCE',
            'fresh_chain_reads': False,
            'limits': ['An inclusion check proves a retained commitment belongs to a published root, not that the record is true.',
                       'The checkpoint chain is derived from anchored batch roots; its head is not a separate on-chain transaction.']}
