# Changelog

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
