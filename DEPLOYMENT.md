# Deployment and verification

Target stable Studionet: RPC https://studio.genlayer.com/api, chain 61999. Reconfirm eth_chainId immediately before signing. Do not use Studio-dev 61997 or substitute a newer RC SDK/runtime.

Use official Python tooling and Studio-compatible accounts; no external browser wallet. Install pinned requirements. Private account keys are local only in `.private/accounts.json`; Studio's built-in faucet supplies simulated GEN. All script calls use `leader_only=False`, with the stable network's default committee. Never publish keys or an unrevealed salt.

Run `bash scripts/check.sh`, ensure a clean git tree, push the source commit, record exact SHA and sha256 of contracts/patchbond.py. `python scripts/live.py deploy` submits exact source bytes and saves its transaction immediately. Poll using `python scripts/live.py poll deployment`: require protocol FINALIZED and GenVM SUCCESS, inspect receipt before using the address, verify source byte equality via RPC, and confirm Explorer recognition. A submitted hash alone is not success.

After confirming deployment, prepare the locked live terms against the recorded baseline fixture commit, fund bounty, and construct the fixed candidate plus pinned attestation. Preserve the candidate as a direct child of that baseline. Push its exact SHA before registering commitment. Capture every receipt. `scripts/live.py` provides bounty/commit/reveal/adjudicate/settle/withdraw commands and LATEST_FINAL readback. Repeat polling rather than resubmitting existing write IDs.

Do not change deployed source unless redeploying and repeating verification. Documentation/fixture commits can follow while the source SHA-256 remains fixed. Verify one-time settlement, bond credit, actual payout delivery and recipient balance delta; `EMITTED` alone is not proof of payment. Hosted Studio's balance behavior is simulated; it does not prove production EVM delivery semantics.

Scripts preserve public receipt evidence under docs/receipts and a machine-readable record. Do not claim a route, address, finalization or test outcome unless observed. Limitations and failures belong in LIVE_VERIFICATION.md, not hidden by retries.
