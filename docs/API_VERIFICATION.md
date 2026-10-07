# Official API verification — 2026-10-07 UTC

Current official sources inspected before implementation:

- https://docs.genlayer.com/full-documentation.txt
- https://docs.genlayer.com/developers/intelligent-contracts/first-contract
- https://docs.genlayer.com/developers/intelligent-contracts/features/transaction-context
- https://docs.genlayer.com/developers/intelligent-contracts/features/value-transfers
- https://docs.genlayer.com/developers/intelligent-contracts/features/messages
- https://docs.genlayer.com/developers/intelligent-contracts/features/web-access
- https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle
- https://docs.genlayer.com/developers/intelligent-contracts/testing
- https://docs.genlayer.com/developers/intelligent-contracts/deploying/network-configuration
- https://docs.genlayer.com/developers/networks
- https://github.com/genlayerlabs/genvm-linter

Stable runtime: GenVM v0.2.16, py-genlayer runner `1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`, std library `11rhn002yfajawsz7fai6mykznbxkxs6l91iskj5cm82c92qhy3v`. Artifacts and their SDK implementation inspected locally. A newer v0.3 RC runner exists; it is not silently substituted into the stable deployment.

Verified: gl.Contract; TreeMap/DynArray/u256 storage; public.view/write/write.payable; gl.message.sender_address/value/chain_id/contract_address/origin_address; deterministic transaction datetime; gl.storage.Root.lock_default; gl.vm.UserError; gl.nondet.web.get/request/render; gl.nondet.exec_prompt(response_format='json'); strict_eq; custom run_nondet_unsafe; self.balance; external Recipient interface emit_transfer.

**Documentation discrepancy:** the current narrative web-access page uses `response.status_code`, but the pinned stable SDK's actual Response fields are `status`, `headers`, `body`. PatchBond uses `response.status`. The actual stable SDK's body is optional bytes; it is checked before decoding. Rendering/POST are available but unused: byte authentication uses GET only. Stable API has no exposed final URL/streaming response cap.

Official tools installed: genlayer-test 0.29.2, genlayer-py 0.16.3, genvm-linter 0.11.0. Direct Mode strict mocks and closure checks are exercised. Unsafe nondeterminism bypasses the Direct Mode automatic pickling check, so tests invoke the official `_validate_pickling` helper explicitly. Linter check/validate/typecheck/schema extraction are recorded separately.

Stable Studionet alias: chain ID 61999, https://studio.genlayer.com/api. Preview Studio-dev: 61997, distinct RC stack. RPC eth_chainId returned 0xf22f (61999). Official Python SDK uses signed local Studio-compatible accounts and Studio's built-in sim_fundAccount faucet mechanism. Its fund_account convenience method is localnet-guarded, so the same documented Studio RPC mechanism is invoked via the SDK provider on Studionet; no chain alias is relabeled. Account secrets stay outside git.

Official network page identifies https://explorer-studio.genlayer.com; the installed SDK's older Explorer preset differs. Live verification must confirm actual Explorer recognition before calling any route verified. CLI supports explicit network selection and deployment; this project uses the official Python SDK instead, as allowed by the brief.
