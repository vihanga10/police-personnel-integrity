# Sepolia finalized deployment verification correction

RPC 1 rejected deployment-height `eth_call` and `eth_getCode` with -32000 historical-state errors. The deployment transaction and saved completion remain preserved.

The checker continues to verify both original receipts, their successful status, the original creation input and signed transaction parameters, the original inclusion block, confirmations and finalized coverage. It reads runtime bytecode and immutable writer/count/chain settings at one numeric block: the lower of the two providers' finalized heights. Both providers must return the same block number and hash. Where that height is a provider's finalized head, its head hash must also match. Both the original inclusion block and the verification block are checked again after state readback.

The checker does not fall back to latest or pending state, accept one provider, skip finality, or suppress a rejected finalized-state request. A changed runtime, writer, chain/count setting, inclusion block or verification block stops validation. A finalized height that has not covered the deployment remains pending.

This verifies the original deployment provenance and the exact contract runtime at the chosen finalized block. It does not claim a newly retrieved archive-state proof at deployment height. The creation input is still checked against the pinned compiler artifact and original immutable writer argument. The contract source and deployed runtime are unchanged.

Existing PREPARED.json and PASSED.json are retained byte-for-byte during read-only validation. Fee caps, wallet files, RPC configuration and journals are unchanged. No transaction is created, replaced or broadcast by installation or validation. Research public publication still requires a new authenticated live evidence/Fabric gate before submission.

Local tests use synthetic fixtures and a compiled local EVM; they do not establish real Sepolia availability. Run the focused tests and commit the source before using the normal deployment VALIDATE command on the Mac. Only after that read-only validation passes should the full guarded public validation run be repeated.
