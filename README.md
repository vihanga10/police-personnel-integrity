# Police Personnel Integrity

A research prototype for **explainable police personnel records**. It answers three questions that a normal "current record" system cannot:

1. **What applied on a date, as known at an earlier time?** (bitemporal history reconstruction)
2. **Who was entitled to approve an action on its date?** (authority and delegation assessment: `VALID`, `INVALID` or `CANNOT_VERIFY`)
3. **Do two reported sources disagree?** (contradiction comparison, with no automatic "correction")

It also keeps an accountable trail: scoped access, independent review, an activity log, and an upload pipeline whose approved records are committed to a private blockchain (Hyperledger Fabric) and a public test network (Ethereum Sepolia).

> **Important:** all data is **synthetic**. It was generated for research (6,596 invented officers across 19 datasets). No real personal or police information is in this repository. This is an undergraduate dissertation prototype, not a production system.

## What it does

| Area | Summary |
|---|---|
| Access | Password plus authenticator code (TOTP), fixed 30-minute sessions, accounts limited to a signed scope |
| History | Reconstructs rank, posting, police number, service status and restrictions for an effective date and a knowledge time; refuses questions outside recorded coverage |
| Authority | Checks the approving actor, rule, scope and delegation chain on the action date |
| Contradictions | Compares claims about the same fact: candidate disagreement, agreement, no conflict, or unresolved |
| Review | Saves findings, requires an independent reviewer (no self-review), keeps every version |
| Upload pipeline | HQ submits a CSV, an independent IGP approves, records are stored encrypted and committed to Fabric and Sepolia, then verified before use |
| Integrity view | Shows an officer's original fingerprint, receipts and checkpoint chain, with a read-only live chain check |
| Recovery | Interrupted operations are retained and recovered without duplicating their effect |

## Repository layout

| Folder | Contents |
|---|---|
| `backend/` | Python 3.12 server (FastAPI), algorithms, access control, import and pipeline tools, tests |
| `frontend/research/` | React 19 interface (built with Vite) and its tests |
| `blockchain/fabric/` | Fabric chaincode, gateway client and workers |
| `blockchain/public/` | Sepolia publication code and tests |
| `contracts/` | Solidity contract (0.8.30) |
| `database/` | PostgreSQL setup |
| `infra/`, `deploy/` | Local service setup and public read-only demo deployment files |
| `docs/examples/`, `docs/*.json` | Example configuration and routing files read by the import code |

## Technology

Python 3.12, FastAPI, SQLAlchemy and Alembic, PostgreSQL 16, MongoDB 8, SQLite (encrypted stores), React 19, Vite, Node.js 24, Hyperledger Fabric 2.5, Solidity 0.8.30, ethers 6, and `uv` for Python packages.

## Running the tests

```bash
# Backend (Python)
cd backend
uv sync
uv run python -m pytest tests

# Frontend
cd frontend/research
npm install
npm test

# Public-chain and Fabric code
cd blockchain/public && npm install && npm test
cd blockchain/fabric/client && node --test test/*.test.js
```

Some backend tests are skipped unless you start the project's isolated PostgreSQL launcher. On macOS, run the Node tests with `TMPDIR` set to a real path, because the default temporary folder is a symbolic link that some tests refuse.

## Running the application

The running system needs **private key files, encrypted stores and local configuration that are deliberately not in this repository**, so cloning it will not give you a working instance. The application also refuses to start if its source files do not match the pins recorded in its configuration. `backend/scripts/serve_public_demo.py` and `backend/scripts/package_public_demo.py` build and serve a read-only copy with no uploads and no chain writes.

## Evaluation summary

On the synthetic corpus, a full run of the automated suites passed all 4,899 tests that were run (89 were skipped because they need a PostgreSQL launcher). All 174 frozen reference cases passed, and three simpler baseline methods scored 31% to 57% on the same cases. The cases were written by the developer, so this shows agreement with the intended rules and not independent validation.

Routine search and profile requests completed within 2.7 seconds. **Warm dashboards took 6.2 to 7.2 seconds against a five-second target, so that target was not met.**

## Limitations

- Synthetic data only; no real police records were used or tested.
- Reference cases were written by one developer, with no second reviewer.
- No user or usability study was carried out.
- Performance was measured on one laptop with one user at a time.
- Fabric and Sepolia behaviour in the tests uses stand-in connections.

## Security

Never commit key material, wallet files, credentials or enrolment files. Keys, stores and configuration live outside the repository.


