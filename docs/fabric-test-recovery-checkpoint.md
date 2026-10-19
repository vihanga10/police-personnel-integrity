# Fabric test network recovery checkpoint

Recorded from operator-supplied Mac output on 2026-10-08 (Asia/Colombo). The genesis repair was committed and pushed as f0bdd29. Focused Mac checks passed: 41 Python tests and 49 Node tests.

The real Fabric checker reported PASSED, 6,596 random test entries, 68 VALID application transactions, four controlled interruptions and matching readback from both peers. The checker also completed conflicting-chunk and ordinary-reader write rejection before reporting PASSED. Test commitments remain retained; no research commitments were submitted.

Network: personnel / officer-evidence-test-v1. Fabric 2.5.16 and CA 1.5.17 ran with recorded native ARM64 images. Setup source revision: ddab9cf44c72f139f62c7919af0fdffba961315a. Recorded samples commit: 5789681b4f4d24e58fa40f19a69f5496892374b6.

Captured genesis whole-file SHA-256: 7e496158e847bd1ed07232f4790331f9ec9a6639e3419e2e98ea55a89948016e.

Content identity policy: FABRIC_GENESIS_HEADER_DATA_V1. Header SHA-256: b9ed551d2ce23b9ac765e6e9e9966ce498e7b09e85450fb98103e38354588cb6. Data SHA-256: 2d4a456cfa91b90cbbd152d47ee960f07a42be2eba401d4a0bedddf42064d434.

Test publication SHA-256: 3ec2b65bad12ede3663026f7c4d57de6d1afeb6c7e11cddec01a0946a1b63048. This describes a random test fixture and must never be substituted for the original research publication SHA-256 fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b.

Private setup/fixture/transaction journals remain under the operator's fabric-local-v1 root, outside Git. Credentials and raw journals are not exported here. This local deployment verification does not establish production availability, independent metadata-signature verification or historical/source truth. Research anchoring, public anchoring and audits remain pending at this checkpoint; classification stays UNASSESSED.
