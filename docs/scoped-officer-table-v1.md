# Scoped officer table

This update replaces the two-button connected list with a paginated signed-directory table. It lists every permitted officer identity, with Name, NIC, division/station and detail availability. It does not generate additional full presentations.

## Accounts

All accounts use the same UI and server-side policy. No individual role can select another role through this endpoint. Existing accounts, passwords and grants are preserved. These are the provisioned simulation scopes; inspect the logged-in scope label if any account was subsequently changed.

| Account | Scope | Expected directory count for the unchanged Stage 3 simulation |
|---|---|---:|
| research.igp | All | 6596 |
| research.hq | All | 6596 |
| research.sdig | RESEARCH_PROVINCE_A | 6596 |
| research.dig.a | RESEARCH_DIVISION_A | 3298 |
| research.dig.b | RESEARCH_DIVISION_B | 3298 |
| research.ssp | RESEARCH_DIVISION_A | 3298 |
| research.sp | RESEARCH_DIVISION_A | 3298 |
| research.oic.a | RESEARCH_STATION_A | 3298 |
| research.oic.b | RESEARCH_STATION_B | 3298 |
| research.inactive | Inactive | Cannot sign in |

These memberships are explicit research simulation, not actual Sri Lanka Police geographical assignments. Station and division counts coincide because the current simulation alternates between two matching groups.

## Install and run

Stop only the HTTPS application with Ctrl+C. Extract this package into Downloads and run:

```bash
bash "$HOME/Downloads/application-scoped-officer-table/run-update.sh"
```

The guarded installer requires the reviewed retained-details v2 source at c8b443a or a clean descendant containing those exact files. It stops on modified prerequisites or a partial installation. It updates source only; it does not open or alter private credentials, stores, datasets or chain journals. Tests and a local source commit follow installation.

Restart using the existing serve_research_workspace.py command. A new full audit/import is not required to use this table with the already-imported retained directory. A future full audit must use a read profile pinned to the then-current committed source.

## Examine one account at a time

Start with research.hq. Sign in, click "Officers and connected detail views in my scope", and leave search blank and availability All officers. The table pages 25 officers at a time. The total should be 6596 under the unchanged imported directory. Choose Details available to inspect the existing connected profiles; choose All officers again for the complete directory.

Search by partial name (including Sinhala), reported NIC text (case-sensitive), or exact immutable officer reference. Row No. is a page position, not a police service number. Police number/rank filters are not supplied because the signed identity directory does not contain assessed values for them. Scope options come only from the signed-in account's permitted directory. Changing filters and pressing Search resets paging. Next/Previous retain the last submitted criteria.

Open details only when Details available is shown. Details unavailable intentionally groups absent/expired/denied presentations so the UI does not assert the reason or bypass disclosure checks. The workspace checks current authorization again when opened.

Sign out, then repeat with IGP, SDIG, DIG A, DIG B, SSP, SP, OIC A, OIC B. Confirm each scope label, total and filter options. The inactive account must fail sign-in. Test direct officer URLs across divisions; they must remain denied. Private table contents and filter values clear at logout, session expiry, backgrounding and page exit. HQ's encrypted exact name/NIC search log captures the new browser endpoint.

## Remaining work

The successful retained import connected only two full officer presentations. This package fixes listing/search/pagination for all permitted directory identities, but it does not complete all 6596 full profiles, live findings anchoring, review authority or independent deployment. It preserves the 30-minute session and existing logs. Automated tests use disposable fixture identities; they do not sign in to the ten private Mac accounts. Graphical browser rendering must be checked on the Mac.
