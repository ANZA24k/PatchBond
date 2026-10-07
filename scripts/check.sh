#!/usr/bin/env bash
set -euo pipefail
python -m pytest tests/direct -q
genvm-lint check contracts/patchbond.py
genvm-lint validate contracts/patchbond.py
genvm-lint typecheck contracts/patchbond.py
genvm-lint schema contracts/patchbond.py --output docs/contract-schema.json
