# Contributing

Device Audit Framework is a research tool. Contributions must preserve its
read-only behavior, reproducibility, and profile-driven rules.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Before submitting changes

Run the same checks used by CI:

```text
python -m pytest -q
python -m compileall -q device_audit device_audit.py
ruff check .
mypy device_audit
git diff --check
```

Use fixture-backed tests for parser and replay changes. Every file under
`tests/fixtures/` participates in a whole-corpus golden digest test and must
remain a permanent regression input. If a fixture changes intentionally,
update the expected digest and the semantic assertion in the same change.

## Safety and scope

- Phase 5 is limited to the existing `network`, `graphics`, `input`, and
  `memory` additions on top of the frozen Phase 1-4 collectors. Do not add
  other Android collectors or whitelist entries in this milestone.
- Do not use `shell=True` or interpolate values into host commands.
- Keep target commands serial-explicit and read-only.
- Redact before writing raw output, metadata, logs, reports, or paths.
- Do not persist full serials or add an unredacted export mode.
- Do not add remote attestation, external-service prediction, remediation,
  package installation, account changes, or device mutation.

## Compatibility

Preserve Phase 1-4 bundle schemas (`1.0`, `2.0`, `3.0`, and `4.0`) and
existing command IDs; Phase 5 uses schema `5.0`. New fields must be optional
for older bundles. Offline analysis must remain deterministic and semantically
equivalent to the composed audit for the same bundle and profile. Unsupported
commands and collector failures must remain recorded rather than aborting
collection.

Audio collection is metadata-only; do not play or record audio. Battery
inventory is not degradation analysis. Thermal collection must not generate
load or change power state. Storage collection must not write, benchmark,
repair, mount, unmount, or format storage. Network collection must not join,
scan, toggle, or probe networks. Graphics collection must not render or
benchmark. Input collection must not sample or inject events. Memory
collection must not run benchmarks or apply memory pressure.

## Pull requests

Describe the research rationale, files changed, fixtures added or updated,
compatibility impact, and validation commands. Do not include live device
serials or unredacted artifacts in commits or issues.
