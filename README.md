# PatchBond

**Evidence-bound software patch bounties, adjudicated by GenLayer Intelligent Contracts.**

A sponsor escrows GEN against an exact public GitHub base commit and an immutable acceptance specification. Developers commit, then reveal a commit-pinned patch package. Validators retrieve code and evidence independently, authenticate every byte, inspect the actual patch, and reach consensus about whether it satisfies the specification. Deterministic accounting awards the fixed bounty once.

**Contribution type: Intelligent Contracts.** This repository is the product: no website, wallet connection, authentication, backend, or database.

## Why GenLayer

Hashes and escrow can be deterministic. Whether a patch genuinely solves a bug, whether its tests are meaningful, and whether it hides material security or compatibility regressions usually cannot. GenLayer's native web access, model execution, and validator equivalence policy supply that judgment without a sponsor or centralized reviewer selecting the winner.

## Narrow v1

- Public GitHub only, canonical lowercase `https://github.com/owner/repository`; full 40-character lowercase commit SHAs.
- Candidate has the exact base as its sole direct parent. Merge commits, submodules, symlink changes, incomplete GitHub trees, binary evidence and oversized repositories are unsupported.
- Terms lock when funded: no amendment, cancellation, deadline extension, payout change, or upgrade authority.
- All changed files' existing base/candidate versions must appear in the authenticated evidence. Required test files must appear at the candidate revision. Extra context files may be included within limits.
- At most 12 changed files, 24 evidence entries, 16 KiB per source, 64 KiB total evidence and 64 KiB per GitHub API response; sponsors can tighten limits.
- Static code/test review, **not a secure remote code-execution service**. Committed test reports are author assertions. If terms demand authenticated execution and no evidence supports it, validators must return `INCONCLUSIVE`.
- Original direct originating accounts receive withdrawals. Contract-wallet and delegated-code recipients are outside the supported settlement assumptions. Hosted Studio simulates balances; it is not a production chain with Ghost contracts.

## Flow

1. `create_bounty(terms_json)` receives a positive funded reward through `@gl.public.write.payable`.
2. `commit_patch(bounty_id, commitment)` receives exactly the specified bond. Commitment binds protocol, chain/contract domain, bounty, submitter, complete immutable package and secret salt.
3. `reveal_patch(submission_id, package_json, salt)` must occur at a later transaction timestamp and before the deadline.
4. `adjudicate(submission_id)` invokes independent retrieval and model review. Outcomes are `ACCEPTED`, `REJECTED`, `INVALID_SUBMISSION`, or `INCONCLUSIVE`.
5. The first accepted adjudication in canonical contract transaction order selects the winner. Clients wait for its successful **finalization** before calling `settle_reward`. Reward/bonds become withdrawal credits, never arbitrary model-chosen amounts.
6. `withdraw()` emits an external value-only transfer on finalization. The ledger deliberately calls these funds `emitted`, not verified paid funds. Verify the receipt and recipient balance externally.

`refund_bounty` and `release_bond` are permissionless but pay only the original beneficiary. An active revealed attempt protects the reward until the fixed resolution deadline (submission deadline + 24h). Unrevealed bonds become releasable at the submission deadline; remaining bonds become releasable when a winner exists or the resolution window expires. No semantic slashing.

## Commit-pinned attestation

`patchbond-attestation.json` in the candidate binds protocol, domain, bounty, submitter address, base, requirements hash, nonce and the SHA-256 of a canonical payload manifest **excluding the attestation itself**. The on-chain commitment additionally binds the resulting candidate commit and the attestation fingerprint. This avoids impossible commit/file self-reference.

A copied commitment cannot be revealed by a different address. A copied candidate cannot authenticate its original attestation for another address. Duplicate candidates are reserved only after successful authentication, preventing unauthenticated reveal squatting. This does not prove copyright/authorship or prevent independently repackaging copied code with a different commit and attestation. See [EVIDENCE.md](EVIDENCE.md).

## Consensus and trust

Exact equality applies to Git identities, changed-file sets, byte hashes/lengths and normalized evidence manifests. Semantic consensus compares outcome, satisfied/failed criterion indexes, risk, issue/deviation presence and bounded scores. Each validator refetches and independently judges the sources; it does not grade the leader's prose. All source comments, README text and reports are untrusted prompt data. See [docs/CONSENSUS.md](docs/CONSENSUS.md) and [SECURITY.md](SECURITY.md).

## Checks

Python 3.12+, Node.js for Pyright:

```sh
pip install -r requirements.txt
bash scripts/check.sh
```

Tests use official `genlayer-test` Direct Mode, strict mocks where all calls should execute, explicit closure pickling checks, independent validator agreement/disagreement and deterministic accounting sequences. Full Consensus and external transfers require real Studio verification; local mocks are not proof of deployment or payout. The deliberate baseline fixture is outside default test discovery.

## Review and verification

- Contract: [contracts/patchbond.py](contracts/patchbond.py)
- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Current API decisions: [docs/API_VERIFICATION.md](docs/API_VERIFICATION.md)
- Deployment: [DEPLOYMENT.md](DEPLOYMENT.md)
- Live outcomes, contract address, source hash and exact transactions: [docs/LIVE_VERIFICATION.md](docs/LIVE_VERIFICATION.md)
- Machine-readable receipts: `docs/receipts/`; reproducible CLI: `scripts/live.py`

Future work: verified sandbox-execution receipts, authenticated CI identities, larger paginated tree proofs, more git hosts, contract-wallet settlement with delivery acknowledgments, and optional appeals within application-defined deadlines. No production audit is claimed.
