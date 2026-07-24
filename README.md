# Device Audit Framework

A read-only Android research CLI that captures redacted ADB evidence, replays it offline, and evaluates only explicitly selected profile expectations. Phase 5 adds bounded network/connectivity, graphics, input-device, and memory inventory on top of the frozen Phase 1-4 collectors; it does not infer commercial-device identity or analyze attestation services.

The framework inventories observable evidence. It does not modify the Android device, predict external-service outcomes, or turn an unreferenced difference into a mismatch.

## Source Distribution

The v0.12.0-rc.1 research release candidate is intended for GitHub source distribution. A
source checkout includes the backward-compatible `device_audit.py` launcher,
the installable `device_audit` package, documented sample profiles, release
documentation, and golden fixtures. Build an sdist or wheel locally with
`python -m build` after installing the `dev` extra.

## Requirements

- Python 3.11 or newer
- Android Debug Bridge (`adb`)
- A device you own or are authorized to audit

Runtime code uses only the Python standard library. Development verification uses `pytest` from `requirements.txt`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

For runtime-only installation, use `python -m pip install .`. The installed
console entry point is `device-audit`; `python device_audit.py` remains
supported for source checkouts. Confirm the installed release with
`device-audit --version` or `python -m device_audit --version`.

## Find a Device

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" devices -l
```

```sh
adb devices -l
```

Pass `--serial` whenever more than one ready target exists. Without it, the CLI proceeds only when exactly one target reports the `device` state. The selected full serial is never persisted.

## Run an Audit

The default invocation is the composed `audit` workflow: capture followed by offline analysis.

```powershell
python device_audit.py `
  --adb-path "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" `
  --serial fixture-device:5555 `
  --profile .\profiles\pixel_10_pro_cp1a.json `
  --output-dir .\audit_output\run_001
```

```sh
python device_audit.py \
  --adb-path ./adb \
  --serial fixture-device:5555 \
  --profile ./profiles/pixel_10_pro_cp1a.json \
  --output-dir ./audit_output/run_001
```

The equivalent installed command is:

```sh
device-audit \
  --adb-path ./adb \
  --serial fixture-device:5555 \
  --profile ./profiles/pixel_10_pro_cp1a.json \
  --output-dir ./audit_output/run_001
```

On macOS, use the resolved Android SDK platform-tools executable, for example:

```sh
python3 device_audit.py \
  --adb-path "$HOME/Library/Android/sdk/platform-tools/adb" \
  --serial fixture-device:5555 \
  --profile ./profiles/pixel_10_pro_cp1a.json \
  --output-dir ./audit_output/run_001
```

The explicit equivalent is `python device_audit.py audit ...`.

## Optional Collectors

`audit` and `collect` support these capture controls:

```text
--skip-display
--skip-telephony
--skip-packages
--skip-magisk
--skip-runtime-markers
--skip-camera
--skip-sensors
--skip-hal
--skip-audio
--skip-battery
--skip-thermal
--skip-storage
--skip-network
--skip-graphics
--skip-input
--skip-memory
--package PACKAGE
```

`--package` is repeatable, validates restrictive Android package names, appends to the default package set, and deduplicates deterministically. Defaults are `android`, `com.google.android.gms`, `com.android.vending`, `com.google.android.apps.subscriptions.red`, `com.google.android.googlequicksearchbox`, and `com.google.android.apps.bard`.

For example, collect all enabled inventory sections except root-gated Magisk
inventory while adding one package:

```powershell
python device_audit.py collect `
  --adb-path .\adb.exe `
  --serial fixture-device:5555 `
  --output-dir .\audit_output\capture_001 `
  --skip-magisk `
  --package com.example.research
```

Offline `analyze` reads whatever evidence exists in the bundle. It does not require the original skip flags or a connected device.

## Collect and Replay Separately

```powershell
python device_audit.py collect `
  --adb-path .\adb.exe `
  --serial fixture-device:5555 `
  --output-dir .\audit_output\capture_001

python device_audit.py analyze `
  --bundle .\audit_output\capture_001 `
  --profile .\profiles\pixel_10_pro_cp1a.json `
  --output-dir .\audit_output\analysis_001
```

```sh
python device_audit.py collect \
  --adb-path ./adb \
  --serial fixture-device:5555 \
  --output-dir ./audit_output/capture_001

python device_audit.py analyze \
  --bundle ./audit_output/capture_001 \
  --profile ./profiles/pixel_10_pro_cp1a.json \
  --output-dir ./audit_output/analysis_001
```

## Evidence and Reports

```text
run_001/
├── evidence.json
├── commands.jsonl
├── audit.log
├── report.json
├── report.md
├── summary.txt
└── raw/
    ├── display_wm_size.stdout.txt
    ├── telephony_registry.stdout.txt
    ├── packages_com_google_android_gms_dumpsys.stdout.txt
    ├── magisk_version.stdout.txt
    ├── runtime_processes.stdout.txt
    ├── camera_media_camera.stdout.txt
    ├── sensors_sensorservice.stdout.txt
    ├── hal_lshal.stdout.txt
    ├── network_connectivity.stdout.txt
    ├── graphics_surface_flinger.stdout.txt
    ├── input_dumpsys.stdout.txt
    ├── memory_proc_meminfo.stdout.txt
    └── ...
```

Evidence bundle schema `5.0` adds network, graphics, input, and memory
collector-state metadata while retaining the Phase 1-4 command and artifact
format. The offline reader continues to accept verified schema `1.0`, `2.0`,
`3.0`, and `4.0` bundles.
`evidence.json` records the bundle schema, redacted command metadata,
artifact paths, SHA-256 digests, and an overall bundle digest. Analysis rejects
missing, modified, malformed, undeclared, or path-escaping artifacts.

All persisted text is canonical UTF-8 with LF newlines before hashing. `report.json` records analyzer version, bundle schema/digest, selected profile digest, section states, command provenance, permission limits, timeouts, parse errors, comparisons, findings, and summary counts. `report.md` contains compact parsed observations only; it never embeds full raw dumps.

## Profile Semantics

Profiles are local, version-controlled reference data. A missing expectation means inventory only. There is no hardcoded Android-version, kernel-label, SoC-topology, baseband, vendor-RIL, or package conclusion.

```json
{
  "display": {
    "allowed_physical_sizes": ["1344x2992"],
    "allowed_density_ranges": [{"min": 450, "max": 520}],
    "allowed_refresh_rates": [60.0, 120.0]
  },
  "telephony": {
    "allowed_operator_numeric": ["310012"],
    "allowed_country_iso": ["us"],
    "allowed_network_types": ["NR_SA", "NR_NSA", "LTE"],
    "allowed_ril_vendors": ["Samsung S.LSI Vendor RIL"],
    "allowed_baseband_patterns": ["^g5300g-"]
  },
  "packages": {
    "com.google.android.gms": {
      "required": true,
      "allowed_version_code_ranges": [{"min": 250000000, "max": 999999999}],
      "required_enabled": true,
      "required_not_suspended": true
    }
  }
}
```

Existing identity/build, `kernel.allowed_lineages`, and `native_cpu.allowed_topologies` profile fields remain supported. The bundled Pixel 10 Pro sample intentionally contains identity/build reference data only. Magisk and runtime markers remain inventory-only in Phase 2.

Phase 3 adds optional `camera`, `sensors`, and `hal` references. For example:

```json
{
  "camera": {
    "minimum_camera_count": 2,
    "required_facing": ["front", "back"],
    "required_camera_ids": ["0", "1"],
    "allowed_hardware_levels": ["FULL", "LEVEL_3"],
    "required_capabilities": ["BACKWARD_COMPATIBLE"]
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

Every Phase 3 field is optional. Omitted fields remain inventory only;
unsupported commands, unavailable services, permission limits, timeouts, and
incomplete parsing cannot create a mismatch finding. HAL names such as DRM or
KeyMint may be inventoried when exposed by the device, but this tool does not
analyze DRM, key attestation, Play Integrity, or other remote services.

Phase 4 adds optional `audio`, `battery`, `thermal`, and `storage` references.
They constrain only the fields explicitly present: minimum audio device counts
and required types/formats/rates; present battery, allowed health or plugged
source, level and temperature bounds; thermal service, sensor-type, severity,
temperature, power-service, and wakefulness references; and storage filesystem,
mount, available-space, volume-type, and mount-service references. Audio is
metadata-only (no playback or recording), battery data is not degradation
analysis, thermal collection performs no load generation, and storage performs
no writes or benchmarks. Extra inventory never creates a mismatch.

Phase 5 adds optional `network`, `graphics`, `input`, and `memory` references:

```json
{
  "network": {
    "required_interfaces": ["wlan0"],
    "allowed_transport_types": ["WIFI", "CELLULAR"],
    "require_connectivity_service_available": true
  },
  "graphics": {
    "allowed_gles_vendors": ["ARM"],
    "allowed_gles_renderer_patterns": ["Mali-G7\\d+"],
    "require_surface_flinger_available": true
  },
  "input": {
    "minimum_device_count": 2,
    "required_device_classes": ["TOUCHSCREEN", "KEYBOARD"]
  },
  "memory": {
    "minimum_total_kb": 4194304,
    "maximum_total_kb": 16777216,
    "require_low_ram_flag": false
  }
}
```

Every Phase 5 field is optional and omitted fields remain inventory only.
Network collection never joins, scans, or probes networks; interface addresses,
SSIDs, and MAC addresses are redacted before persistence. Graphics collection
reads reported GLES/Vulkan identity without rendering. Input collection reads
device identity without sampling or injecting events. Memory collection reads
`/proc` totals without benchmarks or pressure tests.

No aggregate consistency, stealth, bypass, integrity, eligibility, or detection score is calculated. The tool does not predict Play Integrity, Google One, or any other external-service behavior.

## Redaction

Redaction occurs before any artifact reaches disk: raw stdout/stderr, command metadata, logs, manifests, reports, generated paths, and target metadata are all redacted. The default redactor covers contextual Android properties and labeled values for serials, IMEI, IMSI, ICCID, MSISDN, subscriber IDs, SIM serials, Android IDs, advertising IDs, UUIDs, email addresses, and phone-number formats. It avoids indiscriminately removing build IDs and version codes.

There is no unredacted export mode. Review redacted artifacts before sharing because Android vendors may expose identifiers in unanticipated formats.

## Read-Only Whitelist

Every target-specific invocation uses `adb -s SERIAL shell` with argument lists; the host never uses `shell=True` or shell interpolation.

```text
adb devices -l
adb -s SERIAL get-state
adb -s SERIAL shell id
adb -s SERIAL shell getenforce
adb -s SERIAL shell getprop
adb -s SERIAL shell uname -a
adb -s SERIAL shell cat /proc/version
adb -s SERIAL shell cat /proc/sys/kernel/osrelease
adb -s SERIAL shell cat /proc/sys/kernel/hostname
adb -s SERIAL shell cat /proc/cmdline
adb -s SERIAL shell cat /proc/cpuinfo
adb -s SERIAL shell getconf _NPROCESSORS_ONLN
adb -s SERIAL shell cat /sys/devices/system/cpu/online
adb -s SERIAL shell wm size
adb -s SERIAL shell wm density
adb -s SERIAL shell dumpsys display
adb -s SERIAL shell dumpsys window displays
adb -s SERIAL shell settings get system display_density_forced
adb -s SERIAL shell dumpsys telephony.registry
adb -s SERIAL shell dumpsys isub
adb -s SERIAL shell dumpsys telecom
adb -s SERIAL shell cmd package path PACKAGE
adb -s SERIAL shell dumpsys package PACKAGE
adb -s SERIAL shell command -v su
adb -s SERIAL shell su -c id
adb -s SERIAL shell getprop ro.sys.cloud.magisk
adb -s SERIAL shell su -c "magisk -v 2>/dev/null"
adb -s SERIAL shell su -c "magisk -V 2>/dev/null"
adb -s SERIAL shell su -c "magisk --path 2>/dev/null"
adb -s SERIAL shell su -c "magisk --sqlite \"select key,value from settings;\" 2>/dev/null"
adb -s SERIAL shell su -c "ls -1 /data/adb/modules 2>/dev/null"
adb -s SERIAL shell mount
adb -s SERIAL shell cat /proc/mounts
adb -s SERIAL shell ps -A
adb -s SERIAL shell service list
adb -s SERIAL shell ls -la /debug_ramdisk
adb -s SERIAL shell su -c "ls -la /data/adb 2>/dev/null"
adb -s SERIAL shell su -c "ls -la /data/adb/modules 2>/dev/null"
adb -s SERIAL shell su -c "ls -la /data/adb/magisk 2>/dev/null"
adb -s SERIAL shell dumpsys media.camera
adb -s SERIAL shell cmd media.camera list
adb -s SERIAL shell cmd media.camera dump
adb -s SERIAL shell dumpsys sensorservice
adb -s SERIAL shell lshal
adb -s SERIAL shell lshal -i
adb -s SERIAL shell dumpsys -l
adb -s SERIAL shell dumpsys audio
adb -s SERIAL shell dumpsys media.audio_flinger
adb -s SERIAL shell dumpsys media.audio_policy
adb -s SERIAL shell cmd media.audio_policy list-audio-ports
adb -s SERIAL shell cmd media.audio_policy list-audio-patches
adb -s SERIAL shell dumpsys battery
adb -s SERIAL shell dumpsys batteryproperties
adb -s SERIAL shell cmd battery get-status
adb -s SERIAL shell cmd battery get-health
adb -s SERIAL shell cmd battery get-level
adb -s SERIAL shell cmd battery get-plugged
adb -s SERIAL shell cmd battery get-current
adb -s SERIAL shell cmd battery get-temperature
adb -s SERIAL shell cmd battery get-counter
adb -s SERIAL shell cmd battery get-charging-status
adb -s SERIAL shell dumpsys thermalservice
adb -s SERIAL shell dumpsys power
adb -s SERIAL shell dumpsys deviceidle
adb -s SERIAL shell cmd thermalservice dump
adb -s SERIAL shell cmd power get-mode
adb -s SERIAL shell cmd power get-fixed-performance-mode-enabled
adb -s SERIAL shell df -k
adb -s SERIAL shell mount
adb -s SERIAL shell cat /proc/mounts
adb -s SERIAL shell cat /proc/filesystems
adb -s SERIAL shell cat /proc/partitions
adb -s SERIAL shell dumpsys mount
adb -s SERIAL shell sm list-volumes all
adb -s SERIAL shell sm list-disks
adb -s SERIAL shell sm get-primary-storage-uuid
adb -s SERIAL shell dumpsys connectivity
adb -s SERIAL shell ip link
adb -s SERIAL shell cmd wifi status
adb -s SERIAL shell settings get global airplane_mode_on
adb -s SERIAL shell settings get global bluetooth_on
adb -s SERIAL shell dumpsys SurfaceFlinger
adb -s SERIAL shell dumpsys gpu
adb -s SERIAL shell getprop ro.hardware.egl
adb -s SERIAL shell getprop ro.hardware.vulkan
adb -s SERIAL shell dumpsys input
adb -s SERIAL shell cat /proc/bus/input/devices
adb -s SERIAL shell cat /proc/meminfo
adb -s SERIAL shell cat /proc/swaps
adb -s SERIAL shell getprop ro.config.low_ram
```

Root-gated commands execute only after `command -v su` and `su -c id` successfully establish UID 0. They are bounded read-only inventory commands; the tool does not recurse through `/data/adb` or read module files.

The tool never runs `setprop`, `resetprop`, installation/removal commands, app-data clearing, permission changes, Magisk settings changes, Zygisk/DenyList/module changes, SELinux changes, account changes, hooks, interception, remote attestation, or external-service requests.

## Exit Codes

| Code | Meaning |
| ---: | --- |
| 0 | Completed without collector errors |
| 1 | Completed and produced artifacts, but one or more collectors failed |
| 2 | Invalid CLI input, profile, or evidence bundle |
| 3 | ADB executable unavailable |
| 4 | Device missing, ambiguous, unauthorized, offline, or no longer ready |
| 5 | Artifact writing failure |

Profile findings do not make the process exit non-zero.

## Verify

```powershell
python -m pytest -q
python -m compileall -q device_audit device_audit.py
ruff check .
mypy device_audit
git diff --check
```

The fixture and mocked-subprocess test suite does not require a connected Android device.

## Maintainer documentation

- `docs/ARCHITECTURE.md` — module boundaries and safety invariants
- `docs/BUNDLE_FORMAT.md` — bundle layout, digests, redaction, compatibility
- `docs/PROFILE_SCHEMA.md` — explicit reference profile fields
- `docs/COLLECTOR_API.md` — stable collector plugin contract
- `docs/RULE_ENGINE.md` — comparison and finding semantics
- `CONTRIBUTING.md` — development workflow and release-frozen safety rules
