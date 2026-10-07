# Architecture

One non-upgradable Python Intelligent Contract owns storage, escrow, validation and policy. TreeMaps store canonical compact bounty/submission records and unique commitment/candidate keys; a TreeMap stores beneficiary credits; a DynArray records append-only events. Source bodies stay in nondeterministic transient memory; compact authenticated manifests and judgments persist.

Bounty states: LOCKED -> ACTIVE -> WINNER_SELECTED -> REWARD_CREDITED, or LOCKED/ACTIVE -> REFUND_CREDITED. Submission states: COMMITTED -> REVEALED -> ADJUDICATED; winner then SETTLED. Unrevealed/unresolved/losing live attempts can become EXPIRED when their bond-release conditions hold. Every adjudicated bond is already credited once. INCONCLUSIVE is terminal for that attempt, and another authenticated candidate can be attempted before the deadline.

All funding, authorization, limits, hashes, deadlines, duplicates, credit values and state changes run deterministically. `judge` runs in an isolated nondeterministic closure capturing plain memory JSON values rather than storage-backed references. Both leader and validator call it independently. Authorization uses message sender, never a caller-provided beneficiary. Semantic output cannot name a recipient or payment amount.

Two-phase application settlement: a successful final adjudication determines winner; settle_reward credits the immutable amount; withdraw emits the finalization message. No on-accepted transfer is used. Clients must read LATEST_FINAL and verify GenVM SUCCESS separately from consensus ACCEPTED/FINALIZED. The contract cannot query its own receipt's protocol status: canonical order supplies winner selection; operational finality is verified by clients and recorded live.
