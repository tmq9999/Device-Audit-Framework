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

- `schema_version`: `"1.0"` for Phase 1, `"2.0"` for Phase 2, `"3.0"` for
  Phase 3 metadata, or `"4.0"` for Phase 4 metadata.
- `bundle_type`: `"device-audit-evidence"`.
- `generated_at` and `tool_version`.
- `target.serial`, always the literal `"<redacted-serial>"`.
- `commands`, including redacted command arguments, status, timing, raw
  artifact paths, lengths, and SHA-256 digests.
- `commands_jsonl_sha256` and `audit_log_sha256`.
- `bundle_digest`, calculated over the manifest without its own digest field.
- `collector_states` in schemas `2.0`, `3.0`, and `4.0`. Schema `3.0` adds
  `camera`, `sensors`, and `hal`; schema `4.0` adds `audio`, `battery`,
  `thermal`, and `storage`.

Raw stdout and stderr are canonical UTF-8 with LF newlines before hashing.
The loader verifies each raw artifact, the command log, the audit log, and the
manifest digest. Artifact paths must remain inside the bundle directory.

## Status values

Command and section state values are `observed`, `not_evaluated`, `timeout`,
`permission_denied`, `unsupported`, `unavailable`, or `parse_error` where
applicable. `matched` and `mismatched` are analysis comparison states rather
than capture states. A command failure is represented in the bundle;
successful commands remain replayable.

## Compatibility

The loader accepts schemas `1.0`, `2.0`, `3.0`, and `4.0`. Schema `1.0` bundles have
no `collector_states`; offline analysis derives legacy section states from
command evidence and treats absent optional sections as `not_evaluated`.
Schema `2.0` adds Phase 2 collector-state metadata. Schema `3.0` adds Phase 3
collector states and accepts the `unsupported` state used for Android-version
dependent camera, audio-policy, battery, thermal, and storage commands. Schema
`4.0` is additive; older command and artifact representations remain unchanged
and are never rewritten.

The loader verifies that every file under `raw/` is declared by a manifest
command. Missing or extra raw artifacts, modified metadata, future schemas,
and path escapes are rejected before parsing.

Changing a raw file, manifest field, command log, audit log, or digest makes a
bundle invalid. Re-run capture rather than repairing a bundle by hand.

## Redaction

Redaction is applied to raw text, stderr, command arguments, logs, manifest
metadata, reports, and output directory names before persistence. Full serials
are never persisted, and v0.10.0-rc.1 has no unredacted export mode. Phase 4
also contextually redacts UUIDs, volume/disk IDs, audio sessions, client or
process identifiers, package-private paths, MAC/IP addresses, and tokens.
