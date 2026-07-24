# Historical Specification Notice

The original implementation-planning document previously stored at this path
described exploratory work that predates the v0.9.0 release candidate. It is
retained only to preserve the documented filename for existing checkouts and
links; it is not a current product specification.

## Current v0.11.0-rc.1 Scope

Device Audit Framework v0.11.0-rc.1 is a read-only, profile-driven research CLI. It
contains the frozen Phase 1/2 collectors, focused Phase 3 hardware inventory,
focused Phase 4 system inventory, and focused Phase 5 connectivity and
peripheral inventory collectors:

- transport, properties, kernel, and native CPU inventory;
- display, telephony, package, Google Play services, Magisk, and runtime
  inventory;
- bounded camera, sensor, HAL, and native-service inventory;
- bounded audio, battery, thermal/power, and storage inventory;
- bounded network, graphics, input-device, and memory inventory; and
- offline bundle replay and explicit-profile comparison.

It does not add Android commands beyond the documented whitelist, alter a
device, perform spoofing, call remote attestation or external services, make
Play Integrity or eligibility predictions, or calculate bypass/detection
scores.

## Normative Documentation

- `README.md` describes installation, CLI use, the frozen whitelist, replay,
  redaction, and safety guarantees.
- `docs/ARCHITECTURE.md` defines module boundaries and collector orchestration.
- `docs/BUNDLE_FORMAT.md` defines evidence bundle schemas `1.0`, `2.0`,
  `3.0`, `4.0`, and `5.0`.
- `docs/PROFILE_SCHEMA.md` defines explicit reference profiles.
- `docs/COLLECTOR_API.md` defines the stable collector API and its limitations.
- `docs/RULE_ENGINE.md` defines inventory and profile-driven finding behavior.
- `CONTRIBUTING.md` defines compatibility and release-freeze requirements.

For release decisions, these current documents supersede this historical note.
