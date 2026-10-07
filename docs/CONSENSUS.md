# Explicit equivalence policy

The supported API is `gl.vm.run_nondet_unsafe(leader, validator)`. Closures carry ordinary memory dictionaries, never TreeMaps. Each validator independently calls `fetch_evidence` and `judge`; it receives neither the leader reasoning nor leader judgment in its prompt.

The normalized proof includes repository, exact base/candidate commit and tree identities, changed paths, generated URLs, SHA-256, byte lengths, Git blob identities and payload hash. Leader and validator proofs require exact structural equality. This embeds strict equality for objective data inside one custom validator, avoiding a second network retrieval block or storing source bodies in an intermediate consensus receipt. `gl.eq_principle.strict_eq` is supported but unnecessary for this combined flow.

The judgment requires exact outcome, sorted satisfied/failed criterion indexes and risk enum; issue/deviation presence must match. Four integer scores must differ by at most 10 points and must stay on the same side of the 80-point acceptance threshold. Prose/citation selection need not be identical, but every leader citation is validated against its authenticated manifest. An accepted patch must satisfy every criterion, pass every score gate, have LOW risk, no material issues/deviations and cite evidence. Financial policy depends only on that validated outcome.

INVALID_SUBMISSION is determined by objective evidence rules, never the LLM. Inaccessible evidence or malformed/unavailable LLM judgment produces INCONCLUSIVE. Independent inconsistent evidence/outcomes reject the leader result. Contract transactions that become undetermined do not produce authoritative storage verdicts; a later release/refund path works after expiry.

Direct tests capture and rerun the actual validator closure. These prove the policy's mocked behavior, not real committee consensus. Full Consensus evidence must include independent validator executions and successful finalized receipts. See LIVE_VERIFICATION.md for observed results.
