# Security model

## Untrusted interpretation

Repository code/comments, malicious test logs, documentation and sponsor requirement text are evidence, never policy instructions. The fixed prompt instructs every validator to ignore embedded commands and independently inspect all supplied versions. Strict schema/gates prevent malformed model output from becoming acceptance. Prompt injection can still influence a model: this boundary and independent consensus reduce risk, not eliminate it. No source code is executed inside the contract. Semantic review cannot prove arbitrary program correctness or absence of every vulnerability.

## Authentication and retrieval

Branches cannot substitute for commits. Full SHAs, parent identity, complete trees, hashes, lengths and regular-file modes detect substitutions and missing changed-file evidence. Canonical fixed-host URL generation rejects parser ambiguity, credentials, private/loopback targets, malformed encodings and traversal. Observable 3xx responses are invalid. The stable web SDK exposes `status`, `headers`, `body`, but not final URL, redirect history, streaming size caps or DNS addresses: hidden host-followed redirects cannot be audited by the contract. This limitation must not be presented as complete redirect or DNS pinning protection. Only GitHub endpoints are requested; there is no arbitrary URL fetch method. Body checks occur after download; network/GenVM resource limits still matter for oversized responses.

HTTP unavailability yields `INCONCLUSIVE`; objective mismatch yields `INVALID_SUBMISSION`. GitHub rate limits and API outages can prevent adjudication. Unexpected runtime failures or validator disagreement do not authoritatively create a verdict; timeout/release functions provide a deterministic escrow exit after the fixed resolution period.

## Identity, copies, replay

Commit/reveal includes domain, sender, bounty, full package and secret salt. A pinned attestation names that sender and payload. A copier can submit but cannot authenticate the original attestation for its own address. Candidate deduplication happens only after authentication, preventing reservation attacks by invalid copies. This is address binding, not proof of authorship; re-authored copies remain a plagiarism-policy question. Commitments and package nonce/salt should have 256-bit entropy. Maximum submission slots and validator resource limits make capacity exhaustion possible; bonds are refunded, not an effective Sybil resistance mechanism.

## Sponsor and time

Terms and reward lock at creation. No cancel/edit/admin/upgrade method exists; code slots lock without an upgrader. GenVM's transaction clock is deterministic across validators. Commit/reveal cutoff is strict `< deadline`; adjudication cutoff is strict `< deadline+86400`. Revealed attempts block refunds through the resolution window. After that window a sponsor can recover the reward even if a patch has not reached consensus; this is the explicit liveness/fairness tradeoff. No guarantee exists that slow transactions finalize before their window expires.

## Accounting and messages

`funded = escrow + claimable + emitted`. Reward settlement and sponsor refunds are one-time terminal transitions. Bonds always return, including rejected, invalid, inconclusive, expired and losing attempts. Anyone can release funds only to the recorded beneficiary. Withdrawal checks credit and host balance, clears credit once, and uses the documented external EOA interface; external messages execute on finalization. It does not use an IC child transaction that could fail without returning value.

**Supported recipients are original direct originating EOAs.** Sender/origin equality excludes nested contract callers but is not a code-presence or delegated-account proof. Contract wallets/delegated code are unsupported. External message failure has no reliable in-contract acknowledgement or safe retry path in this API: v1 cannot promise recovery for rejecting contract recipients. The ledger records EMITTED, never a fabricated delivery confirmation. Review the emitted-message receipt and balance delta. A production rollout requires stronger EOA validation or an acknowledged recipient adapter. Hosted Studio has simulated balances/no EVM Ghost layer; successful hosted tests do not verify production external-message behavior.

GenVM transaction reverts protect state/message atomicity. Direct Mode does not emulate every runtime/transfer failure or consensus/finality rule. Malicious recipients, infrastructure bugs, forced value transfers and underlying protocol failures are outside the modeled no-stuck-escrow invariant. The contract has no arbitrary surplus sweep: externally forced/unaccounted transfers are not sponsor bounty deposits.

## Disclosure

Open a private GitHub security advisory where supported; do not post exploit instructions or secrets in public issues. No production deployment or independent security audit is claimed.
