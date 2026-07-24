# Changelog

## 0.10.0 RC 1 — tag `v0.10.0-rc.1`

- Add bounded, read-only camera inventory without opening devices or capturing
  images.
- Add sensorservice inventory without activating sensors or sampling events.
- Add HAL and native-service inventory through `lshal`, `dumpsys -l`, and
  reused Phase 2 evidence.
- Introduce evidence bundle schema `3.0` while preserving schema `1.0` and
  `2.0` offline replay and digest verification.
- Add `--skip-camera`, `--skip-sensors`, and `--skip-hal` capture controls.
- Add optional profile-driven camera, sensor, and HAL comparisons; omitted
  references remain inventory-only.
- Preserve unsupported commands, permission limits, timeouts, and partial
  parser results without aborting successful collectors.
- Retain the strict read-only whitelist and make no DRM, KeyMint, attestation,
  Play Integrity, eligibility, or other external-service conclusions.
- Document that vendor text formats may remain partially parsed and that
  permission-restricted services can produce incomplete inventory.

## 0.9.0 RC 2 — tag `v0.9.0-rc.2`

- Define an explicit Ruff lint rule set so CI remains stable across compatible
  Ruff releases.

## 0.9.0 RC 1 — tag `v0.9.0-rc.1`

- Freeze the Phase 1/2 read-only command set for research reproducibility.
- Add the versioned `Collector` API and migrate built-in collectors without
  changing command IDs or observable capture behavior.
- Publish installable package metadata and the `device-audit` console entry
  point.
- Preserve offline replay for evidence bundle schemas `1.0` and `2.0`.
- Add CI for pytest, mypy, Ruff, compileall, and isolated package smoke tests.
- Document architecture, bundle format, profile schema, collector API, rule
  engine, and contributor safety requirements.
