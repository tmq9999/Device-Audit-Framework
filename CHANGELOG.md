# Changelog

## 0.11.0 RC 1 — tag `v0.11.0-rc.1`

- Add read-only `audio`, `battery`, `thermal`, and `storage` collectors through
  the stable Collector API.
- Introduce additive evidence bundle schema `4.0` while preserving offline
  replay and digest verification for schemas `1.0`, `2.0`, and `3.0`.
- Add bounded audio route/service metadata, battery and charging state,
  thermal/power state, and storage mount/volume/filesystem summaries.
- Add `--skip-audio`, `--skip-battery`, `--skip-thermal`, and `--skip-storage`.
- Add explicit opt-in profile references and mismatch rules for each Phase 4
  section; omitted or incomplete evidence remains inventory-only.
- Add eight synthetic Phase 4 fixture families and a committed schema `4.0`
  replay bundle, increasing the locked corpus to 440 files.
- Validate explicit `--serial` targets directly without running global
  `adb devices -l` discovery.
- Lock the golden fixture corpus to committed bytes via `.gitattributes` so
  the corpus digest matches on every checkout platform.
- Preserve read-only collection: no playback, recording, power mutation,
  thermal stress, storage writes, benchmarks, or second full `getprop`.

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
