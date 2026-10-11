// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Dedicated append-only opaque findings publications on Sepolia.
/// @dev Writer authentication does not verify Fabric receipts or off-chain facts.
/// The protected adapter must verify those before submission. No upgrade/admin path.
contract FindingsAnchor {
    uint256 public constant CHAIN_ID = 11155111;
    string public constant POLICY = "FINDINGS_PUBLIC_ANCHOR_V1";
    string public constant NAMESPACE = "findings-anchor-v1";
    address public immutable writer;

    struct Publication {
        // Exact coordinator order: public_sha256, merkle_root,
        // fabric_destination_sha256, fabric_transaction_id, fabric_receipt_sha256.
        bytes32[5] metadata;
        uint256 recordedBlock;
    }
    mapping(bytes32 => Publication) private publications;
    event Published(bytes32 indexed publicationId, bytes32 publicSha256,
        bytes32 merkleRoot, bytes32 fabricDestinationSha256,
        bytes32 fabricTransactionId, bytes32 fabricReceiptSha256);

    constructor(address writer_) {
        require(block.chainid == CHAIN_ID, "Sepolia chain required");
        require(writer_ != address(0), "zero writer");
        writer = writer_;
    }

    function publish(bytes32 publicationId, bytes32[5] calldata metadata) external {
        require(msg.sender == writer, "writer required");
        require(msg.data.length == 196, "exact publication calldata required");
        require(publicationId != bytes32(0), "zero publication");
        for (uint256 i; i < 5; ++i) require(metadata[i] != bytes32(0), "zero metadata");
        Publication storage p = publications[publicationId];
        if (p.metadata[0] != bytes32(0)) {
            for (uint256 i; i < 5; ++i)
                require(p.metadata[i] == metadata[i], "publication conflict");
            return; // No storage writes or event on an exact authorized retry.
        }
        p.metadata = metadata;
        // Chain observation only; never an evidence intake/effective timestamp.
        p.recordedBlock = block.number;
        emit Published(publicationId, metadata[0], metadata[1], metadata[2], metadata[3], metadata[4]);
    }

    function readPublication(bytes32 publicationId) external view
        returns (bytes32[5] memory metadata, uint256 recordedBlock) {
        require(msg.data.length == 36, "exact read calldata required");
        Publication storage p = publications[publicationId];
        require(p.metadata[0] != bytes32(0), "publication absent");
        return (p.metadata, p.recordedBlock);
    }
}
