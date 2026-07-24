# Architecture

Device Audit Framework is a read-only, profile-driven evidence tool. The
runtime is standard-library-only; development dependencies provide tests,
linting, type checking, and packaging.

## Data flow

```text
CLI
  ├─ capture: discover target → select serial → run registry → write bundle
  └─ analyze: verify bundle → parse artifacts → compare profile → render reports
```

`audit` composes the two paths. `collect` stops after a verified evidence
bundle is written. `analyze` never contacts ADB and can replay a bundle on a
different host.

## Modules

- `device_audit.adb` owns subprocess execution, target selection, timeouts,
  and serial-explicit `adb -s SERIAL shell ...` invocation.
- `device_audit.collector_api` defines the stable `Collector` protocol,
  bounded `CommandSpec` objects, shared collector context, result values, and
  ordered registry.
- `device_audit.collectors.builtin` contains the frozen Phase 1/2 groups and
  the bounded Phase 3 `camera`, `sensors`, and `hal` groups. It is the
  authoritative command whitelist for the branch.
- `device_audit.capture` performs discovery, readiness checks, registry
  orchestration, and bundle persistence.
- `device_audit.bundle` writes canonical redacted artifacts and verifies
  schema, path containment, metadata, and SHA-256 digests during replay.
- `device_audit.parsers` converts raw text into normalized observations. A
  parser may return incomplete data; it must not infer unobserved facts.
- `device_audit.profiles` validates explicit JSON reference profiles.
- `device_audit.rules` produces `matched`, `mismatched`, or `not_evaluated`
  comparisons only for profile-declared expectations.
- `device_audit.analysis` coordinates offline parsing and produces JSON,
  Markdown, and plain-text summaries.
- `device_audit.redaction` runs before any persisted artifact is written.

## Collector boundaries

Collectors do not receive a raw shell interface. They return `CommandSpec`
instances and execute them through `CollectorContext.run`, which delegates to
the serial-bound ADB client. A collector can share bounded state with later
collectors, such as the read-only root probe result. The registry preserves
declaration order and rejects duplicate collector IDs and command IDs.

No automatic third-party plugin discovery is enabled in v0.9.0. External
collectors must be explicitly reviewed and injected through the registry.
This keeps the command whitelist auditable and reproducible.

## Safety invariants

- Host subprocesses use argument lists and `shell=False`.
- Every target shell command is run with the selected serial.
- The Android command set is frozen for this Phase 3 milestone; no collector
  outside camera, sensors, and HAL/native-service inventory is included.
- Root-gated commands run only after a successful read-only UID 0 probe.
- Collection errors become evidence states and do not discard successful
  sections; unexpected plugin exceptions are recorded and later collectors
  continue.
- Reports contain compact parsed observations, never full raw dumps.
- Camera, sensor, and HAL summaries are bounded and deterministically ordered;
  complete redacted command output remains available only in raw artifacts.
- Unsupported Phase 3 commands are recorded as evidence and do not abort other
  collectors.
- The framework never calculates stealth, bypass, integrity, eligibility, or
  detection scores and never predicts external-service outcomes.
