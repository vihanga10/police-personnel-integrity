# Fabric genesis identity repair v1

The first real test checker stopped before fixture creation because it compared the entire orderer-fetched block against the peer-returned block. Operator diagnostics showed identical serialized header and data digests for the saved block and both peers, with different metadata digests. Fabric committers add validation information to block metadata; metadata is excluded from Fabric's block hash computation. Reference: https://github.com/hyperledger/fabric/blob/main/docs/source/ledger/ledger.md and https://hyperledger.github.io/fabric-protos/protos.html .

This repair retains the saved block's exact whole-file SHA-256 verification against the existing private gateway configuration. It additionally decodes the known Block framing, checks genesis number zero, empty previous hash, required header data hash and nonempty data, and compares the exact header/data digests against each peer. Unknown/duplicate/truncated fields fail closed. Metadata must be structurally parseable but is excluded from this content-identity comparison. These content digests are an application identity policy, not Fabric's ASN.1 block-header hash and not independent verification of all metadata signatures. TLS, MSP authorization, both-organization endorsement and VALID commit-status checks remain required.

The network journal descriptor retains the original capture SHA-256 and adds `FABRIC_GENESIS_HEADER_DATA_V1` plus header/data digests. This repair is limited to the first checker failure before any fixture/prepared/submitted/receipt files. The runtime repair refuses a nonempty journal directory, changed original gateway, changed saved genesis file, unexpected test chaincode or preexisting helper. It saves the original gateway privately and updates only two runtime JavaScript files. No configuration, wallet, ledger, journal or personnel database is modified. Test contract redeployment is unnecessary.

## Verification and commit

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m pytest -q --tb=short \
    tests/test_fabric_gateway_repair.py tests/test_anchor_gate.py
cd ..
node --test \
    blockchain/fabric/client/test/block-identity.test.js \
    blockchain/fabric/client/test/journal.test.js \
    blockchain/fabric/chaincode/test/evidence.test.js

git add backend/scripts/repair_fabric_gateway.py \
    backend/tests/test_fabric_gateway_repair.py \
    blockchain/fabric/client/gateway.js \
    blockchain/fabric/client/block-identity.js \
    blockchain/fabric/client/test/block-identity.test.js \
    docs/fabric-genesis-identity-v1.md
git diff --cached --check &&
git commit -m "Verify Fabric genesis contents across orderer and peer metadata" &&
git push
```

## Update the preserved runtime client

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m scripts.repair_fabric_gateway \
    --network-root "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1"
```

Run once after committing. If refused, preserve the original runtime and journals and inspect the aggregate reason. Do not delete journals or recreate the network to bypass the guard.

## Rerun the real checker

```bash
node "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1/runtime/client/check-network.js" \
    "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1/gateway-config.json" \
    "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1/recovery-checks"
```

This remains the random test-only workflow: 6,596 entries, 68 original VALID transactions, controlled interruptions and two-peer readback. Successful local unit tests do not establish real network recovery; retain the Mac's actual checker result. Research commitments, public anchoring and audit execution remain pending. Classification stays UNASSESSED.
