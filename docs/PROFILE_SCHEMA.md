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
  "packages": {},
  "camera": {},
  "sensors": {},
  "hal": {}
}
```

`schema_version` must begin with `1.`, `2.`, or `3.`. `name` is required. All
other sections are optional and default to empty reference data.

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

## Phase 3 hardware references

Phase 3 references are opt-in and compare only normalized inventory fields:

```json
{
  "camera": {
    "minimum_camera_count": 2,
    "required_facing": ["front", "back"],
    "required_camera_ids": ["0", "1"],
    "allowed_hardware_levels": ["FULL", "LEVEL_3"],
    "required_capabilities": ["BACKWARD_COMPATIBLE", "LOGICAL_MULTI_CAMERA"]
  },
  "sensors": {
    "minimum_sensor_count": 3,
    "required_types": ["android.sensor.accelerometer"],
    "allowed_vendors": ["Synthetic Sensors"]
  },
  "hal": {
    "required_interfaces": ["android.hardware.camera.provider"],
    "required_families": ["android.hardware.camera"],
    "allowed_transports": ["hwbinder", "binder", "passthrough"]
  }
}
```

Supported camera fields are `minimum_camera_count`, `required_facing`
(`front`, `back`, `external`, or `unknown`), `required_camera_ids`,
`allowed_hardware_levels` (`LEGACY`, `LIMITED`, `FULL`, `LEVEL_3`, `EXTERNAL`,
or `UNKNOWN`), and `required_capabilities`. Supported sensor fields are
`minimum_sensor_count`, `required_types`, and `allowed_vendors`. Type keys
prefer the service's declared Android string type and fall back to a stable
name for recognized numeric types. Supported HAL
fields are `required_interfaces`, `required_families`, and
`allowed_transports` (`hwbinder`, `binder`, `vndbinder`, `passthrough`, or
`unknown`).

Omitting a Phase 3 field means inventory only. The framework does not infer
camera-to-device identity, sensor-to-SoC compatibility, or the meaning of an
inventoried DRM, KeyMint, or other native service. Unsupported commands,
permission errors, timeouts, and incomplete parser output are not mismatch
evidence.

## Findings

The rule engine emits a finding only for a `mismatched` comparison whose
expectation exists in the selected profile. Missing evidence is
`not_evaluated`, not a mismatch. Unreferenced observations remain inventory.

The bundled `profiles/pixel_10_pro_cp1a.json` is identity/build reference data
only; it intentionally does not assert a native kernel or CPU reference.
