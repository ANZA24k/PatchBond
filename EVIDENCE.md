# Canonical evidence and identities

Serialization is UTF-8 JSON: sorted keys, compact separators, ASCII escapes, no NaN. All integers are exact; floats/bools are rejected for financial/schema numbers. Duplicate JSON keys are rejected in terms, packages, attestations and API objects. Arrays preserve order; package evidence is lexicographically sorted by `(revision,path)` and unique.

Terms fields are enumerated in `validate_terms`. The requirements hash is SHA-256 of their canonical serialization. Deadline, bond, scope, repository and base are included; funded reward is separately immutable and recorded at creation.

Package:

```json
{"candidate_commit":"<40 lowercase hex>","nonce":"<64 lowercase hex>","evidence":[{"revision":"base","path":"fixtures/live_patch/clamp.py","sha256":"<64 lowercase hex>","bytes":123},{"revision":"candidate","path":"patchbond-attestation.json","sha256":"<64 lowercase hex>","bytes":456}]}
```

Real packages also include every changed file version and required tests. Callers cannot supply URLs: validators construct HTTPS GitHub API and raw URLs from the validated repository, exact commit and safe ASCII relative path. No branch names, ports, userinfo, query/fragment input, percent encoding or arbitrary hosts are accepted. GitHub tree requests use an internally generated `?recursive=1`.

Attestation exact fields: `protocol`, `domain` (`chain_id`, lowercase `contract`), `bounty`, lowercase `submitter`, `requirements_hash`, `base_commit`, `nonce`, `payload_hash`. Payload is the package evidence array excluding every entry with reserved attestation path. It commits file hashes and lengths without referring to the Git commit that contains it. A separate secret 32-byte hex salt is never placed in the attestation.

Commitment canonical object: `protocol`, `domain`, `bounty`, `submitter`, `package`, `salt`. The actual candidate commit is known when this object is constructed. Chain and contract domain prevent cross-deployment replay.

Validators retrieve base/candidate Git commit metadata, complete recursive Git trees, and each raw file. They check direct-parent ancestry, regular file modes, scope, changed-file coverage, UTF-8, lengths, SHA-256 and Git blob SHA-1 identity. SHA-1 is used only for compatibility with GitHub's Git object identities; the package independently commits SHA-256.

Sources remain dependent on GitHub TLS and API integrity/availability. GitHub API responses are not cryptographically signed. Changed trees are not fully reconstructed into Git tree hash proofs. Immutable references do not guarantee perpetual public availability. Committed test reports prove their bytes exist, not that a CI job actually ran. Arbitrary CI artifacts and release URLs are unsupported in v1.

Decision hash binds protocol, domain, bounty, terms hash, submission, original submitter, candidate, authenticated proof hash, normalized judgment and deterministic transaction timestamp. Historical verdicts are never rewritten. Events append transition hashes and amounts; full current records contain the immutable verdict.
