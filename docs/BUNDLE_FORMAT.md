# Evidence Bundle Format

An evidence bundle is a local, redacted research artifact. It is shareable
only after the redaction guarantees have been reviewed for the target.

## Layout

```text
bundle/
├── evidence.json
├── commands.jsonl
├── audit.log
└── raw/
    ├── <safe-command-id>.stdout.txt
    └── <safe-command-id>.stderr.txt
```

Analysis output is normally written beside the bundle as `report.json`,
`report.md`, and `summary.txt`; those report files are not required to replay
the evidence bundle.

## Manifest

`evidence.json` contains:

- `schema_version`: `"1.0"` for Phase 1 or `"2.0"` for Phase 2 metadata.
- `bundle_type`: `"device-audit-evidence"`.
- `generated_at` and `tool_version`.
- `target.serial`, always the literal `"<redacted-serial>"`.
- `commands`, including redacted command arguments, status, timing, raw
  artifact paths, lengths, and SHA-256 digests.
- `commands_jsonl_sha256` and `audit_log_sha256`.
- `bundle_digest`, calculated over the manifest without its own digest field.
- `collector_states` in schema `2.0`, with one state for each Phase 2
  collector section.

Raw stdout and stderr are canonical UTF-8 with LF newlines before hashing.
The loader verifies each raw artifact, the command log, the audit log, and the
manifest digest. Artifact paths must remain inside the bundle directory.

## Status values

Command and section state values are `observed`, `matched`, `mismatched`,
`not_evaluated`, `timeout`, `permission_denied`, `unavailable`, or
`parse_error` where applicable. A capture failure is represented in the
bundle; successful commands remain replayable.

## Compatibility

The v0.9.0 loader accepts both schema `1.0` and schema `2.0`. Schema `1.0`
bundles have no `collector_states`; offline analysis derives legacy section
states from command evidence and treats absent Phase 2 sections as
`not_evaluated`. Schema `2.0` adds collector-state metadata without changing
the Phase 1 command/artifact representation.

Changing a raw file, manifest field, command log, audit log, or digest makes a
bundle invalid. Re-run capture rather than repairing a bundle by hand.

## Redaction

Redaction is applied to raw text, stderr, command arguments, logs, manifest
metadata, reports, and output directory names before persistence. Full serials
are never persisted, and v0.9.0 has no unredacted export mode.
