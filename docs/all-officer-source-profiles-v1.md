# All officer source profiles

## What is connected

This update connects every anchored officer's complete original subject rows, including personal, service, family, education and source history records. It uses a single full original replay and a single subject index. The UI displays the reported current division/station fields from officer_service_information.csv, separately from server-owned access membership. Authorized rows open by row click or Open details. Unknown posting values remain unknown.

Profiles have a dedicated Ed25519 signing domain, source-publication/context bindings, per-profile digests and an authenticated set manifest. Profile records and manifests are encrypted with the separate workspace key. Publication is one SQLite transaction. All older source-profile generations, recorded presentations, protected histories, findings, requests and access logs remain retained. An incomplete import rolls back the new generation and its grants.

The exact source replay checks, owner-only file checks, source artifact pins, source/UI key separation and ten-minute fresh audit permit remain enforced. The new CLI performs a full audit before the bulk connection and checks the permit again before commit. It does not create per-officer witness listeners, synthesize past observation timestamps, submit chains, alter original rows or silently extend readiness. Source copy issuance is actual import time and is not historical knowledge coverage.

## Install and connect

Stop the HTTPS server with Ctrl+C. Keep PostgreSQL, MongoDB and Fabric running. Extract this ZIP into Downloads. It requires the already-installed scoped officer table and retained-details v2 at c8b443a ancestry, with clean source.

```bash
bash "$HOME/Downloads/application-all-officer-profiles/run-complete.sh"
```

The script installs guarded source, runs tests, commits only reviewed files, creates a private read profile pinned to the resulting revision, then performs the fresh full audit and bulk connection. Paste your existing tokenized QuickNode Sepolia HTTPS endpoint at the hidden prompt. An upgrade is not part of this step. If the named profile already exists it is reused and verified; a changed revision fails rather than silently editing its pins. Never share its URL or JSON.

Success must print ALL_FULL_SOURCE_PROFILES_IMPORTED, full_source_profiles_connected: 6596, and all_officer_source_details_connected: true. This is pending until your Mac completes it. The original audit can take time; the bulk projection adds one indexed pass, rather than 6596 full replays. Actual dataset runtime is not established by fixture timings.

Restart with your existing serve_research_workspace.py command and sign in again. HQ and IGP should browse all 6596 identities and open their source records. The other active accounts can open only their signed current scopes. The inactive account remains denied. Source-profile copies have no five-minute expiry; the 30-minute session and current bounded account/disclosure authorizations remain enforced. This is a one-time connection, not a recurring five-minute audit.

## Research workflow boundary

Full source records include the original transfer, promotion, restriction, conduct, complaint and court rows associated with that officer. These rows are reported evidence, not accepted personnel facts or approved authority.

The two previously connected witnessed history/findings workspaces are preserved. Other officers now receive a full source profile, while historical query/review controls explain that no witnessed recording workspace is connected. This bulk step does not create new recording journals or findings, claim journal coverage, or complete findings anchoring. Source history tables can be read in Overview. Extending witnessed algorithm workspaces remains a separate task; no empty result is presented as proof of agreement.

Current division and station in the table are explicitly reported source fields, not verified current accepted state. Access filters still use signed simulated membership, now labelled Access scope; they do not infer authorization from posting values. Existing scope assignments and passwords are preserved.

## Validation

Tests exercise real signatures/encryption, complete 6596-profile atomic publication, missing/tampered profile rejection, rollback, source-posting derivation, subject-only projection, preservation of existing histories, all ten role/scope cases and exact search accountability. The original replay loader is replaced only inside disposable integration fixtures; no test claims the user's live files were read. Existing DOM privacy/countdown and workflow tests remain included. Graphical rendering and real Mac readiness are verified separately by running the script and checking the application.
