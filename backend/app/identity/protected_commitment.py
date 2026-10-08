"""Versioned, domain-separated protected commitments; no ledger client or source exports."""
import base64
from collections import Counter
import hashlib
import hmac
import re
from uuid import UUID

from app.identity.destination_binding import POLICY as DESTINATION_POLICY, slot, require
from app.identity.evidence_bundle_v2 import POLICY as BUNDLE_POLICY, canonical

POLICY = 'OFFICER_PROTECTED_COMMITMENT_V1'
KEY_POLICY = 'OFFICER_COMMITMENT_KEYS_V1'
HEX = re.compile(r'[0-9a-f]{64}')


def encoded(value):
    return canonical(value).encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


class CommitmentKeys:
    """Keep publication pseudonyms separate from content commitments and identity keys."""
    def __init__(self, data):
        require(set(data) == {'policy', 'version', 'content_key', 'publication_key'} and
                data['policy'] == KEY_POLICY and data['version'] == 'commit-v1', 'Commitment key configuration differs.')
        self.version = data['version']
        self.content = base64.b64decode(data['content_key'], validate=True)
        self.publication = base64.b64decode(data['publication_key'], validate=True)
        require(len(self.content) == len(self.publication) == 32 and
                not hmac.compare_digest(self.content, self.publication), 'Separate 32-byte commitment keys required.')

    def assert_separate(self, crypto):
        for key in (*crypto.encryption_keys.values(), *crypto.lookup_keys.values()):
            require(not hmac.compare_digest(key, self.content) and not hmac.compare_digest(key, self.publication),
                    'Commitment keys must differ from identity keys.')

    def commit(self, domain, payload):
        # Arrays frame domains and payloads unambiguously; source text is never normalized.
        return hmac.new(self.content, encoded([POLICY, self.version, domain, payload]), hashlib.sha256).hexdigest()

    def handle(self, domain, payload):
        return hmac.new(self.publication, encoded([POLICY, self.version, domain, payload]), hashlib.sha256).hexdigest()


def merkle_root(leaves):
    """Ordered tree: SHA256(0x00 || canonical leaf), SHA256(0x01 || left || right).

    Odd final nodes duplicate themselves. This root supplements individual commitments.
    """
    require(bool(leaves), 'Empty commitment tree.')
    nodes = [hashlib.sha256(b'\x00' + encoded(leaf)).digest() for leaf in leaves]
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [hashlib.sha256(b'\x01' + nodes[i] + nodes[i+1]).digest() for i in range(0, len(nodes), 2)]
    return nodes[0].hex()


def validate_inventory(manifest, catalog, bindings, sql_counts, mongo_counts):
    """Check membership and every captured destination slot before commitment generation."""
    require(manifest['policy'] == BUNDLE_POLICY and bindings['policy'] == DESTINATION_POLICY and
            bindings['source_snapshot'] == manifest['snapshot'] and bindings['source_bundle_policy'] == BUNDLE_POLICY,
            'Source/destination snapshot differs.')
    officers = [b['officer_uid'] for b in manifest['bundles']]
    require(officers and len(officers) == len(set(officers)), 'Repeated or missing officer.')
    require(all(str(UUID(o)) == o for o in officers), 'Officer UUID differs.')
    require(set(bindings['raw_bindings']) == set(catalog) and
            set(bindings['officer_bindings']) == set(officers), 'Destination universe differs.')
    require(bindings['sql_table_counts'] == sql_counts and
            bindings['sql_records'] == sum(sql_counts.values()) and
            bindings['mongo_documents'] == sum(mongo_counts.values()), 'Destination scope/counts differ.')
    expected_edges = {o: {} for o in officers}
    for raw, row in catalog.items():
        require(HEX.fullmatch(raw) and row['raw_record_id'] == raw and row['classification'] == 'UNASSESSED' and
                row['delivery']['complete'] is True, 'Source row state differs.')
        require(len(row['original']['columns']) == len(row['original']['values']), 'Source field coverage differs.')
        require(bool(bindings['raw_bindings'][raw]), 'Source destination binding missing.')
        seen_links = set()
        for link in row['candidate_links']:
            officer, role = link['officer_uid'], link['role']
            require(officer in expected_edges and isinstance(role, str) and role and
                    link['state'] == 'CANDIDATE_NOT_ACCEPTED', 'Candidate membership differs.')
            require((officer, role) not in seen_links, 'Repeated candidate membership.')
            seen_links.add((officer, role))
            expected_edges[officer].setdefault((row['filename'], raw), set()).add(role)
    for bundle in manifest['bundles']:
        require(bundle['policy'] == BUNDLE_POLICY and bundle['snapshot'] == manifest['snapshot'] and
                bundle['bundle_version'] == 2, 'Officer bundle version differs.')
        actual = {}
        for edge in bundle['evidence']:
            identifier = (edge['filename'], edge['raw_record_id'])
            require(identifier not in actual and edge['linkage_accepted'] is False and
                    len(edge['candidate_roles']) == len(set(edge['candidate_roles'])), 'Officer membership repeated or accepted.')
            actual[identifier] = set(edge['candidate_roles'])
        require(actual == expected_edges[bundle['officer_uid']], 'Catalog/officer memberships differ.')
    require(manifest['received_rows'] == len(catalog) and
            manifest.get('associated_rows', 0) == sum(bool(r['candidate_links']) for r in catalog.values()) and
            manifest.get('unassigned_rows', 0) == sum(not r['candidate_links'] for r in catalog.values()), 'Source coverage differs.')
    seen_sql, seen_mongo = set(), set()
    sql_seen, mongo_seen = Counter(), Counter()
    buckets = [*bindings['raw_bindings'].values(), *bindings['officer_bindings'].values(), bindings['shared_bindings']]
    for bucket in buckets:
        for item in bucket:
            if item.get('store') == 'mongodb':
                require(set(item) == {'store', 'collection', 'document_id', 'document_sha256'} and
                        item['collection'] in mongo_counts and isinstance(item['document_id'], str) and
                        HEX.fullmatch(item['document_sha256']), 'Mongo binding shape differs.')
                key = (item['collection'], item['document_id'])
                require(key not in seen_mongo, 'Repeated Mongo destination.')
                seen_mongo.add(key); mongo_seen[item['collection']] += 1
            else:
                require(set(item) == {'table', 'primary_key', 'row_sha256', 'columns'} and
                        item['table'] in sql_counts and HEX.fullmatch(item['row_sha256']) and item['primary_key'] and
                        item['columns'] == sorted(set(item['columns'])), 'SQL binding shape differs.')
                require(all(isinstance(pair, list) and len(pair) == 2 and pair[0] in item['columns'] for pair in item['primary_key']),
                        'SQL primary-key coverage differs.')
                key = slot(item)
                require(key not in seen_sql, 'Repeated SQL destination.')
                seen_sql.add(key); sql_seen[item['table']] += 1
    # Empty scoped tables are still part of the declared snapshot (classification has zero rows).
    require({name: sql_seen[name] for name in sql_counts} == sql_counts and
            {name: mongo_seen[name] for name in mongo_counts} == mongo_counts, 'Captured destination coverage differs.')


def ordered(items):
    return sorted(items, key=canonical)


def generate(manifest, catalog, bindings, keys, *, generator_revision, sql_counts, mongo_counts):
    validate_inventory(manifest, catalog, bindings, sql_counts, mongo_counts)
    require(re.fullmatch(r'[0-9a-f]{40}', generator_revision), 'Committed generator revision required.')
    context = dict(policy=POLICY, commitment_version=1, key_version=keys.version,
                   snapshot=manifest['snapshot'], bundle_policy=manifest['policy'],
                   court_membership_policy=manifest['court_membership_policy'],
                   destination_policy=bindings['policy'], binding_revision=bindings['collector_revision'],
                   binding_collected_at=bindings['collected_at'], source_attempt_id=bindings['source_attempt_id'],
                   generator_revision=generator_revision,
                   sql_table_counts=sql_counts, mongo_collection_counts=mongo_counts)
    raw_commitments = {}
    for raw, row in sorted(catalog.items()):
        # Edge sets are ordered; original column/value and reported participant order remain significant.
        source = dict(row, candidate_links=ordered(row['candidate_links']))
        raw_commitments[raw] = keys.commit('SOURCE_ROW', dict(context=context, source=source,
                                                destinations=ordered(bindings['raw_bindings'][raw])))
    shared = keys.commit('SHARED_CONTEXT', dict(context=context, destinations=ordered(bindings['shared_bindings']),
                          unassigned=[dict(raw_record_id=r, commitment=raw_commitments[r])
                                      for r in sorted(catalog) if not catalog[r]['candidate_links']]))
    public_records, private_officers = [], []
    for bundle in sorted(manifest['bundles'], key=lambda b: b['officer_uid']):
        officer = bundle['officer_uid']
        publication = keys.handle('OFFICER_PUBLICATION', dict(snapshot=manifest['snapshot'], officer_uid=officer))
        membership = [dict(edge, candidate_roles=sorted(edge['candidate_roles']), source_commitment=raw_commitments[edge['raw_record_id']])
                      for edge in ordered(bundle['evidence'])]
        normalized = dict(bundle, evidence=membership)
        commitment = keys.commit('OFFICER_BUNDLE', dict(context=context, publication_id=publication,
                       bundle=normalized, officer_destinations=ordered(bindings['officer_bindings'][officer]), shared_commitment=shared))
        public_records.append(dict(publication_id=publication, commitment_version=1, commitment=commitment))
        private_officers.append(dict(officer_uid=officer, publication_id=publication, commitment=commitment))
    public_records.sort(key=lambda r: r['publication_id'])
    require(len({r['publication_id'] for r in public_records}) == len(public_records) and
            len({r['commitment'] for r in public_records}) == len(public_records), 'Commitment/publication collision.')
    coverage = keys.commit('ALL_SOURCE_COVERAGE', dict(context=context, rows=raw_commitments))
    batch_id = keys.handle('BATCH_PUBLICATION', context)
    batch_commitment = keys.commit('BATCH', dict(context=context, publication_id=batch_id,
                             officers=public_records, shared_commitment=shared, coverage_commitment=coverage))
    # The typed batch leaf covers shared/unassigned evidence even if officer leaves are independently anchored.
    leaves = [dict(kind='OFFICER', **r) for r in public_records] + [dict(kind='BATCH', publication_id=batch_id, commitment=batch_commitment)]
    public = dict(policy=POLICY, commitment_version=1, key_version=keys.version, batch_publication_id=batch_id,
                  officers=public_records, shared_commitment=shared, coverage_commitment=coverage,
                  batch_commitment=batch_commitment, merkle_root=merkle_root(leaves))
    private = dict(context=context, officers=private_officers, raw_commitments=raw_commitments, public=public)
    return public, private
