# Consolidated findings Fabric integration corrections

## Scope and evidence

This patch is for the uploaded launcher, peer-check and material files after the October 11 corrections. The installer checks 20 exact source prerequisites, including those uploaded bytes before changes. It updates six source/test files and adds four. It does not run Docker, provision research storage, create production keys, deploy contracts, select an existing network or submit research commitments. No push. RPC 1 remains deferred.

Confirmed from the supplied Mac logs:

- Original peers treated a bracketed comma-separated CA list as one filename. The uploaded launcher already combines both trusted roots in an owner-only PEM bundle. Mutual TLS stays enabled.
- Original build context omitted block-identity.js. The uploaded launcher already includes it. A new dependency-closure test covers relative requires in the explicit source whitelist.
- Original enrollment certificates had TLS clientAuth EKU. The uploaded material.js correctly omits that EKU for enrollment certificates and retains it for the separate TLS client. This patch checks material.js but does not replace it.
- Original genesis block permissions were not owner-only. The uploaded launcher already chmods that fixture file to 600.
- Supplied lifecycle query hex vectors have identical definition fields and approval values, but different map-entry order. Raw hash equality was unsuitable for repeated map responses.
- A no-such-transaction response is an observation failure, not proof of absence or permission to broadcast another transaction. The previous run may have stopped between durable attempt retention and actual submission because of the unstable definition pin. That cause cannot be established from the supplied logs alone. Delayed indexing is also possible.

## Explicit definition pin policy

FINDINGS_AUTHENTICATED_GATEWAY_V2 uses the domain-separated FINDINGS_DEFINITION_APPROVAL_ORDER_V2 digest. The bounded parser checks top-level QueryChaincodeDefinitionResult fields 1 through 8 and sorts approval entries by their UTF-8 key bytes. It preserves the exact bytes of sequence, version, endorsement plugin, validation plugin, validation parameter, collection configuration and init-required; it preserves every approval key/value entry. Unknown fields, duplicate singleton fields, duplicate approval keys, noncanonical varints, invalid booleans, unsupported entry encodings, oversized and truncated messages fail closed. Nested collection/validation bytes remain exact; no definition attributes are discarded.

The digest normalizes singleton field order and approvals entry order, but does not equate every protobuf encoding of optional defaults or nested messages. This deliberately may reject other semantically equivalent encodings. It has only been exercised against the captured vectors, official protobuf classes and offline tests; genuine peers still need to pass.

V1 configurations continue using their original raw-byte hash policy. They are not silently migrated. V2 remains bound by the exact externally approved configuration hash, signed bridge selection and each organization's pinned digest. Fresh disposable fixture configurations select V2. There is no production configuration migration or change to contract authorization, transaction binding, VALID flags or exact two-organization readback checks.

## Observation and recovery

V2 retries only QSCC reads of the retained original transaction ID. Bounded attempts (30), 500 ms intervals and a 30-second elapsed budget apply between requests. Individual RPCs retain the Gateway's 60-second deadline, so a request in flight can exceed the polling budget. Only gRPC UNAVAILABLE/DEADLINE_EXCEEDED or UNKNOWN with the exact requested ID in a no-such-transaction index error qualify. Other errors fail immediately. Exhaustion propagates uncertainty, never ABSENT. No wait helper can endorse, submit or replace a transaction.

The protected bridge and its durable before-submission attempt marker are unchanged. No automatic resubmission occurs after that marker, including when broadcasting never happened. Such a retained operation requires supervised recovery. Fresh disposable runs always have fresh scoped histories; the harness never repairs or deletes previous retained histories. Entire-directory rollback resistance and operational full-replay loader integration remain pending.

## Harness checks and limits

The first protected execution now runs once; observation retries are reads inside the Gateway. It is no longer retried as a whole protected operation. Expected writer-denial, conflicting-publication and extra-field checks require the actual chaincode reason; an unrelated connection failure cannot satisfy them. Each completed peer check is printed. Fixture approvals retain a bounded maximum ten-minute window. Test certificate issuance remains offline fixture CA signing, not a Fabric CA service deployment/enrollment test.

The previously added private service-log capture and redacted error details remain. Containers, private network and owned SDK image are cleaned up with exact run labels; shared images are preserved. The network still has no host ports, existing ledger volumes or Docker socket. SIGKILL, host crash or unavailable Docker can prevent cleanup; no broad cleanup/reset is provided.

## Validation completed here

- 214 Node tests passed, zero failures/skips. Includes 9 genuine SDK/protobuf/contract/shim checks and 205 offline parser, adapter-double, retention and chaincode tests.
- 14 Python launcher tests passed, including source dependency closure and single-path mutual TLS CA configuration.
- Patched certificate issuance was checked with OpenSSL for enrollment and TLS-client chain/purpose validation.
- Syntax checks, guarded installer scenarios and package inventory checks completed.
- Docker is unavailable in the development environment. No Docker build or actual peer execution of this consolidated patch has passed here. Mac validation is required.

This verifies implementation checks, not research algorithm accuracy, production deployment readiness or live findings anchoring. Backend loader integration, independent recovery protection, deployed witnesses/authority configuration and live research execution remain pending.
