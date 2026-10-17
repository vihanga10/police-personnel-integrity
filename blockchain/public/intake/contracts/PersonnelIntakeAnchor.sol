// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Dedicated append-only opaque dataset-intake publications on Sepolia.
/// @dev Records a registered dataset code and five commitments only. Writer
/// authentication does not verify Fabric receipts or off-chain facts; the
/// protected adapter verifies those first. No upgrade, admin or delete path.
contract PersonnelIntakeAnchor {
    uint256 public constant CHAIN_ID = 11155111;
    string public constant POLICY = "PERSONNEL_INTAKE_PUBLIC_ANCHOR_V1";
    string public constant NAMESPACE = "personnel-intake-anchor-v1";
    address public immutable writer;

    struct Publication {
        bytes32 dataset;
        // Exact coordinator order: public_sha256, merkle_root,
        // fabric_destination_sha256, fabric_transaction_id, fabric_receipt_sha256.
        bytes32[5] metadata;
        uint256 recordedBlock;
    }
    mapping(bytes32 => Publication) private publications;
    event Published(bytes32 indexed publicationId, bytes32 indexed dataset, bytes32 publicSha256,
        bytes32 merkleRoot, bytes32 fabricDestinationSha256, bytes32 fabricTransactionId, bytes32 fabricReceiptSha256);

    constructor(address writer_) {
        require(block.chainid == CHAIN_ID, "Sepolia chain required");
        require(writer_ != address(0), "zero writer");
        writer = writer_;
    }

    function publish(bytes32 publicationId, bytes32 dataset, bytes32[5] calldata metadata) external {
        require(msg.sender == writer, "writer required");
        require(msg.data.length == 228, "exact publication calldata required");
        require(publicationId != bytes32(0) && dataset != bytes32(0), "zero publication");
        for (uint256 i; i < 5; ++i) require(metadata[i] != bytes32(0), "zero metadata");
        Publication storage p = publications[publicationId];
        if (p.metadata[0] != bytes32(0)) {
            require(p.dataset == dataset, "publication conflict");
            for (uint256 i; i < 5; ++i)
                require(p.metadata[i] == metadata[i], "publication conflict");
            return; // No storage writes or event on an exact authorized retry.
        }
        p.dataset = dataset;
        p.metadata = metadata;
        // Chain observation only; never an evidence intake/effective timestamp.
        p.recordedBlock = block.number;
        emit Published(publicationId, dataset, metadata[0], metadata[1], metadata[2], metadata[3], metadata[4]);
    }

    function readPublication(bytes32 publicationId) external view
        returns (bytes32 dataset, bytes32[5] memory metadata, uint256 recordedBlock) {
        require(msg.data.length == 36, "exact read calldata required");
        Publication storage p = publications[publicationId];
        require(p.metadata[0] != bytes32(0), "publication absent");
        return (p.dataset, p.metadata, p.recordedBlock);
    }
}
