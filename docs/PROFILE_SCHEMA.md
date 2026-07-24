# Profile Schema

Profiles are versioned, local, explicit reference data. They are not Android
truth tables and are never inferred from the target.

## Root object

```json
{
  "schema_version": "1.0",
  "name": "Reference name",
  "identity": {},
  "build": {},
  "kernel": {},
  "native_cpu": {},
  "display": {},
  "telephony": {},
  "packages": {}
}
```

`schema_version` must begin with `1.` or `2.`. `name` is required. All other
sections are optional and default to empty reference data.

## Identity and build

Identity keys map to observable properties: `brand`, `manufacturer`, `model`,
`device`, and `product`. Build keys map to `id`, `incremental`, `release`,
`sdk`, `security_patch`, `fingerprint`, and `description`.

Only keys present in the selected profile are compared. Values are strings in
the normalized profile model; integer JSON values are accepted where the
implementation normalizes them to strings.

## Native references

Kernel and CPU comparisons are opt-in:

```json
{
  "kernel": {
    "allowed_lineages": ["android13-5.10"]
  },
  "native_cpu": {
    "allowed_topologies": [
      {
        "online_cpu_count": 8,
        "clusters": [
          {"implementer": "0x41", "part": "0xd05", "count": 4},
          {"implementer": "0x41", "part": "0xd41", "count": 2},
          {"implementer": "0x41", "part": "0xd44", "count": 2}
        ]
      }
    ]
  }
}
```

Omitting either field means inventory only. An `android13` kernel is not
invalid merely because the host or a researcher expected Android 16. A55,
A78, X1, or any other CPU parts are not declared compatible or incompatible
with a SoC name unless the selected profile explicitly says so.

## Phase 2 references

Phase 2 supports optional display, telephony, and package expectations:

- `display.allowed_physical_sizes`: strings such as `"1344x2992"`.
- `display.allowed_density_ranges`: objects with integer `min` and `max`.
- `display.allowed_refresh_rates`: positive numbers.
- `telephony.allowed_operator_numeric`, `allowed_country_iso`,
  `allowed_network_types`, `allowed_ril_vendors`, and
  `allowed_baseband_patterns`.
- `packages.<package>` with `required`, version-code ranges,
  `required_enabled`, and `required_not_suspended`.

All optional reference lists are empty by default. Regex values are validated
before analysis. Package names use a restrictive Android package-name
pattern.

## Findings

The rule engine emits a finding only for a `mismatched` comparison whose
expectation exists in the selected profile. Missing evidence is
`not_evaluated`, not a mismatch. Unreferenced observations remain inventory.

The bundled `profiles/pixel_10_pro_cp1a.json` is identity/build reference data
only; it intentionally does not assert a native kernel or CPU reference.
