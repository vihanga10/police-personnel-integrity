// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Append-only received-batch v1 commitments. No personal data or audit decisions.
/// @dev Exact SHA-256 JSON leaves match OFFICER_PROTECTED_COMMITMENT_V1.
contract OfficerEvidence {
    uint256 public constant CHAIN_ID = 11155111;
    uint256 public constant OFFICERS = 6596;
    uint256 public constant LEAVES = 6597;
    uint256 public constant CHUNK_SIZE = 100;
    address public immutable writer;
    struct Batch {
        // public payload digest, Merkle root, shared, coverage, batch commitment
        bytes32[5] metadata;
        uint256 count;
        bytes32 lastHandle;
        bool exists;
        bool isSealed;
    }
    mapping(bytes32 => Batch) private batches;
    mapping(bytes32 => mapping(bytes32 => bytes32)) private records;
    mapping(bytes32 => mapping(uint256 => bytes32)) private chunks;
    event Created(bytes32 indexed batch, bytes32 payload, bytes32 root);
    event Appended(bytes32 indexed batch, uint256 indexed start, uint256 count);
    event Sealed(bytes32 indexed batch, bytes32 root);
    modifier onlyWriter() { require(msg.sender == writer, "writer required"); _; }
    constructor(address writer_) {
        require(block.chainid == CHAIN_ID, "Sepolia chain required");
        require(writer_ != address(0), "zero writer");
        writer = writer_;
    }
    function createBatch(bytes32 batch, bytes32[5] calldata metadata, bytes32[] calldata proof) external onlyWriter {
        require(batch != bytes32(0), "zero batch");
        for (uint256 i; i < 5; ++i) require(metadata[i] != bytes32(0), "zero metadata");
        bytes32 leaf = sha256(abi.encodePacked(bytes1(0), '{"commitment":"', hex32(metadata[4]),
            '","kind":"BATCH","publication_id":"', hex32(batch), '"}'));
        require(verify(leaf, OFFICERS, proof, metadata[1]), "batch proof differs");
        Batch storage b = batches[batch];
        if (b.exists) {
            require(keccak256(abi.encode(b.metadata)) == keccak256(abi.encode(metadata)), "batch conflict");
            return;
        }
        b.metadata = metadata;
        b.exists = true;
        emit Created(batch, metadata[0], metadata[1]);
    }
    function appendOfficers(bytes32 batch, uint256 start, bytes32[] calldata handles,
        bytes32[] calldata commitments, bytes32[][] calldata proofs) external onlyWriter {
        Batch storage b = batches[batch];
        require(b.exists, "batch absent");
        require(start < OFFICERS && start % CHUNK_SIZE == 0, "chunk position differs");
        uint256 n = OFFICERS - start;
        if (n > CHUNK_SIZE) n = CHUNK_SIZE;
        require(handles.length == n && commitments.length == n && proofs.length == n, "chunk size differs");
        // Includes proofs so a retry cannot silently change any prepared call field.
        bytes32 fingerprint = keccak256(abi.encode(handles, commitments, proofs));
        if (chunks[batch][start] != bytes32(0)) {
            require(chunks[batch][start] == fingerprint, "chunk conflict");
            return;
        }
        require(!b.isSealed && start == b.count, "chunk order differs");
        bytes32 previous = b.lastHandle;
        for (uint256 i; i < n; ++i) {
            require(handles[i] > previous && commitments[i] != bytes32(0), "officer order or value differs");
            require(records[batch][handles[i]] == bytes32(0), "duplicate officer");
            require(verify(officerLeaf(handles[i], commitments[i]), start + i, proofs[i], b.metadata[1]), "officer proof differs");
            records[batch][handles[i]] = commitments[i];
            previous = handles[i];
        }
        chunks[batch][start] = fingerprint;
        b.lastHandle = previous;
        b.count += n;
        emit Appended(batch, start, n);
    }
    function sealBatch(bytes32 batch) external onlyWriter {
        Batch storage b = batches[batch];
        require(b.exists && b.count == OFFICERS, "incomplete batch");
        if (b.isSealed) return;
        b.isSealed = true;
        emit Sealed(batch, b.metadata[1]);
    }
    function readBatch(bytes32 batch) external view returns (bytes32[5] memory, uint256, bool) {
        Batch storage b = batches[batch];
        require(b.exists, "batch absent");
        return (b.metadata, b.count, b.isSealed);
    }
    function readOfficer(bytes32 batch, bytes32 handle) external view returns (bytes32) {
        bytes32 value = records[batch][handle];
        require(value != bytes32(0), "officer absent");
        return value;
    }
    function officerLeaf(bytes32 handle, bytes32 commitment) public pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0), '{"commitment":"', hex32(commitment),
            '","commitment_version":1,"kind":"OFFICER","publication_id":"', hex32(handle), '"}'));
    }
    function verify(bytes32 node, uint256 index, bytes32[] calldata proof, bytes32 root) public pure returns (bool) {
        if (index >= LEAVES || proof.length != 13) return false;
        uint256 width = LEAVES;
        for (uint256 i; i < proof.length; ++i) {
            if (width <= 1) return false;
            // Duplicate the last node at each odd level, as the original Python tree does.
            if (index % 2 == 0 && index + 1 == width && proof[i] != node) return false;
            node = index % 2 == 0 ? sha256(abi.encodePacked(bytes1(0x01), node, proof[i]))
                                 : sha256(abi.encodePacked(bytes1(0x01), proof[i], node));
            index /= 2;
            width = (width + 1) / 2;
        }
        return width == 1 && node == root;
    }
    function hex32(bytes32 value) private pure returns (bytes memory result) {
        result = new bytes(64);
        // Each iteration writes exactly two bytes inside the allocated 64-byte result.
        // Table bytes are ASCII lowercase hexadecimal, matching the original JSON.
        assembly ("memory-safe") {
            let alphabet := 0x3031323334353637383961626364656600000000000000000000000000000000
            let output := add(result, 32)
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                let octet := byte(i, value)
                mstore8(add(output, mul(i, 2)), byte(shr(4, octet), alphabet))
                mstore8(add(output, add(mul(i, 2), 1)), byte(and(octet, 15), alphabet))
            }
        }
    }
}
