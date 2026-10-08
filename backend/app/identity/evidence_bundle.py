"""Versioned source-evidence inventories; not commitments or accepted identities."""
import base64
import json
from collections import Counter
from uuid import UUID

POLICY = "OFFICER_EVIDENCE_BUNDLE_FOUNDATION_V1"
UNCERTAINTIES = ["CLASSIFICATION_UNASSESSED", "HISTORICAL_IDENTITY_UNASSESSED",
    "AUTHORITY_UNASSESSED", "SOURCE_INDEPENDENCE_UNVERIFIED", "VALID_PERIODS_UNASSESSED"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    # Deterministic inventories do not normalize, trim or reinterpret source cells.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def uid(value):
    require(isinstance(value, str) and str(UUID(value)) == value, "Officer UUID differs.")
    return value


class BundleInventory:
    """One shared catalog entry per source row, with explicit candidate-role edges."""
    def __init__(self, officers, expected_rows):
        officers = list(officers)
        require(len(officers) == len(set(officers)), "Repeated officer UUID.")
        self.officers = sorted(uid(x) for x in officers)
        self.expected = dict(expected_rows)
        self.catalog = {name: {} for name in self.expected}
        self.edges = {x: {} for x in self.officers}
        self.by_raw = {}

    def add(self, filename, raw_id, original, provenance, associations):
        require(filename in self.catalog, "Unknown source file.")
        require(isinstance(raw_id, str) and len(raw_id) == 64 and all(c in "0123456789abcdef" for c in raw_id), "Raw ID differs.")
        require(raw_id not in self.by_raw, "Repeated source row.")
        require(set(original) == {"columns", "values"} and len(original["columns"]) == len(original["values"]), "Original row shape differs.")
        require(len(original["columns"]) == len(set(original["columns"])) and all(isinstance(x, str) for x in original["columns"] + original["values"]), "Original field types differ.")
        require(provenance.get("source_row_number", 0) > 0, "Source row number differs.")
        links = set()
        for officer, role in associations:
            require(officer in self.edges and isinstance(role, str) and role, "Candidate association differs.")
            links.add((officer, role))
        self.catalog[filename][raw_id] = dict(raw_record_id=raw_id, original=original, provenance=provenance,
            candidate_links=[dict(officer_uid=o, role=r, state="CANDIDATE_NOT_ACCEPTED") for o, r in sorted(links)],
            uncertainty=list(UNCERTAINTIES), classification="UNASSESSED")
        self.by_raw[raw_id] = self.catalog[filename][raw_id]
        for officer, role in links:
            # A shared record is inventoried once, while each officer retains its role.
            self.edges[officer].setdefault((filename, raw_id), set()).add(role)

    def bind_receipt(self, raw_id, receipt, assertion):
        require(raw_id in self.by_raw, "Receipt source missing.")
        row = self.by_raw[raw_id]
        require("delivery" not in row and receipt["complete"], "Repeated or incomplete receipt.")
        row["delivery"] = dict(receipt)
        row["assertion"] = dict(assertion)

    def finish(self, snapshot):
        require(set(snapshot) == {"batch_id", "archive_sha256", "confirmation_sha256", "code_revision", "collection_started_at"}, "Snapshot binding differs.")
        for name, rows in self.catalog.items():
            require(len(rows) == self.expected[name], "Source catalog count differs.")
            require({r["provenance"]["source_row_number"] for r in rows.values()} == set(range(1, len(rows)+1)), "Source sequence differs.")
            require(all("delivery" in r for r in rows.values()), "Source receipt missing.")
        for officer in self.officers:
            profiles = [r for (name, r), roles in self.edges[officer].items()
                if name == 'officer_personal_information.csv' and 'officer_nic_no' in roles]
            if 'officer_personal_information.csv' in self.expected:
                require(len(profiles) == 1, "Officer profile candidate coverage differs.")
        bundles = [dict(officer_uid=o, bundle_version=1, policy=POLICY, snapshot=dict(snapshot),
            evidence=[dict(filename=f, raw_record_id=r, candidate_roles=sorted(roles), linkage_accepted=False)
                for (f, r), roles in sorted(self.edges[o].items())], uncertainty=list(UNCERTAINTIES)) for o in self.officers]
        counts = Counter()
        for rows in self.catalog.values():
            for row in rows.values():
                counts["associated_rows" if row["candidate_links"] else "unassigned_rows"] += 1
        return dict(policy=POLICY, snapshot=dict(snapshot), bundles=bundles,
            catalog_files=sorted(self.catalog), received_rows=sum(self.expected.values()), **counts)


def seal_artifact(crypto, backup, payload, binding):
    context = canonical([POLICY, "ENCRYPTED_MANIFEST", binding])
    cipher, version = crypto.encrypt_assertion(payload, context=context)
    require(crypto.decrypt_assertion(cipher, key_version=version, context=context) == payload, "Primary recovery differs.")
    require(backup.decrypt_assertion(cipher, key_version=version, context=context) == payload, "Backup recovery differs.")
    return dict(policy=POLICY, binding=binding, key_version=version, ciphertext=base64.b64encode(cipher).decode("ascii"))


def open_artifact(crypto, envelope, binding):
    require(set(envelope) == {"policy", "binding", "key_version", "ciphertext"} and envelope["policy"] == POLICY and envelope["binding"] == binding, "Manifest binding differs.")
    return crypto.decrypt_assertion(base64.b64decode(envelope["ciphertext"], validate=True), key_version=envelope["key_version"],
        context=canonical([POLICY, "ENCRYPTED_MANIFEST", binding]))
