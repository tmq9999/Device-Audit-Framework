# Rule Engine

The rule engine separates inventory from comparison.

## Pipeline

1. Parsers normalize raw artifacts into observable models.
2. `compare_profile` creates comparison records for profile-declared fields.
3. Each comparison is `matched`, `mismatched`, or `not_evaluated`.
4. `evaluate_profile` turns only mismatches into neutral findings.

The report retains observations, source command IDs, section states, and
comparison records regardless of whether a profile was selected.

## No implicit conclusions

No finding is emitted for a missing profile, an omitted reference section,
missing evidence, a permission error, a timeout, or a parser that cannot
normalize a value. In all of those cases the result is inventory or
`not_evaluated` state.

The engine does not calculate aggregate consistency, stealth, bypass,
eligibility, integrity, or detection scores. It does not predict Google Play
Integrity, Google One, account, or other external-service behavior.

## Finding categories

- Identity/build mismatches use `PROFILE_FIELD_MISMATCH`.
- Explicit kernel lineage mismatches use `KERNEL_LINEAGE_MISMATCH`.
- Explicit native topology mismatches use `CPU_TOPOLOGY_MISMATCH`.
- Explicit Phase 2 references use display, telephony, or package-specific
  mismatch IDs.
- Explicit Phase 3 references use `CAMERA_PROFILE_MISMATCH`,
  `SENSORS_PROFILE_MISMATCH`, or `HAL_PROFILE_MISMATCH`.
- Explicit Phase 4 references use `AUDIO_PROFILE_MISMATCH`,
  `BATTERY_PROFILE_MISMATCH`, `THERMAL_PROFILE_MISMATCH`, or
  `STORAGE_PROFILE_MISMATCH`.

Camera, sensor, and HAL observations are bounded summaries. Extra cameras,
sensors, interfaces, capabilities, and transports do not create findings when
the profile does not require their absence. Unsupported, permission-denied,
timed-out, unavailable, and incomplete sections remain `not_evaluated` for
profile comparison.

Audio, battery, thermal, and storage observations follow the same rule. The
engine does not infer battery degradation, storage health, thermal quality,
performance, authenticity, integrity, or eligibility. It does not compare
storage UUIDs, disk names, audio effect UUIDs, or transient client identifiers.

Finding severity and confidence describe the comparison evidence; they are
not a device eligibility judgment. Researchers must verify the selected
profile's provenance before interpreting a mismatch.
