"""Offline parsing, profile evaluation, and report rendering."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from device_audit import __version__
from device_audit.bundle import load_evidence_bundle
from device_audit.models import (
    AudioInventory,
    BatteryInventory,
    CameraInventory,
    Comparison,
    CpuTopology,
    DisplayInfo,
    Finding,
    HalInventory,
    KernelInfo,
    MagiskInfo,
    PackageInfo,
    RuntimeMarkers,
    SensorInventory,
    StorageInventory,
    TelephonyInfo,
    ThermalInventory,
)
from device_audit.parsers import (
    parse_camera_info,
    parse_audio_info,
    parse_battery_info,
    parse_cpuinfo,
    parse_display_info,
    parse_hal_info,
    parse_getprop,
    parse_kernel_info,
    parse_magisk_info,
    parse_online_cpu_count,
    parse_package_info,
    parse_runtime_markers,
    parse_sensor_info,
    parse_storage_info,
    parse_telephony_info,
    parse_thermal_info,
)
from device_audit.profiles import load_profile
from device_audit.redaction import redact_text
from device_audit.rules import compare_profile, evaluate_profile


@dataclass(frozen=True)
class AnalysisOutcome:
    """The result of analyzing one evidence bundle."""

    findings: tuple[Finding, ...]
    collector_errors: int
    report_path: Path


def analyze_bundle(
    bundle_dir: Path,
    output_dir: Path,
    profile_path: Path | None = None,
) -> AnalysisOutcome:
    """Analyze a verified bundle without contacting the Android device."""

    bundle_dir = Path(bundle_dir)
    output_dir = Path(output_dir)
    manifest = load_evidence_bundle(bundle_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    command_entries = manifest["commands"]
    commands = {entry["id"]: entry for entry in command_entries}
    collector_states = manifest.get("collector_states", {})

    transport, transport_status = _parse_transport(bundle_dir, commands)
    properties, properties_status = _parse_properties(bundle_dir, commands)
    kernel, kernel_status = _parse_kernel(bundle_dir, commands)
    cpu, cpu_status = _parse_cpu(bundle_dir, commands)
    display, display_status = _parse_display(bundle_dir, commands, collector_states)
    telephony, telephony_status = _parse_telephony(
        bundle_dir,
        commands,
        properties,
        collector_states,
    )
    packages, packages_status = _parse_packages(bundle_dir, command_entries, collector_states)
    magisk, magisk_status = _parse_magisk(bundle_dir, commands, collector_states)
    runtime, runtime_status = _parse_runtime(bundle_dir, commands, collector_states)
    camera, camera_status = _parse_camera(bundle_dir, commands, collector_states)
    sensors, sensors_status = _parse_sensors(bundle_dir, commands, collector_states)
    hal, hal_status = _parse_hal(
        bundle_dir,
        commands,
        properties,
        collector_states,
    )
    audio, audio_status = _parse_audio(bundle_dir, commands, collector_states)
    battery, battery_status = _parse_battery(bundle_dir, commands, collector_states)
    thermal, thermal_status = _parse_thermal(bundle_dir, commands, collector_states)
    storage, storage_status = _parse_storage(bundle_dir, commands, properties, collector_states)

    profile = load_profile(profile_path) if profile_path else None
    comparisons = tuple(
        compare_profile(
            properties,
            kernel,
            cpu,
            profile,
            display,
            telephony,
            packages,
            camera if camera_status == "observed" else None,
            sensors if sensors_status == "observed" else None,
            hal if hal_status == "observed" else None,
            audio if audio_status == "observed" else None,
            battery if battery_status == "observed" else None,
            thermal if thermal_status == "observed" else None,
            storage if storage_status == "observed" else None,
        )
    )
    findings = tuple(
        evaluate_profile(
            properties,
            kernel,
            cpu,
            profile,
            display,
            telephony,
            packages,
            camera if camera_status == "observed" else None,
            sensors if sensors_status == "observed" else None,
            hal if hal_status == "observed" else None,
            audio if audio_status == "observed" else None,
            battery if battery_status == "observed" else None,
            thermal if thermal_status == "observed" else None,
            storage if storage_status == "observed" else None,
        )
    )
    collector_errors = sum(1 for entry in command_entries if entry["status"] != "observed")
    sections = {
        "transport": _section_payload(
            transport_status,
            transport,
            command_entries,
            "transport",
        ),
        "properties": _section_payload(
            properties_status,
            {key: redact_text(value) for key, value in sorted(properties.items())},
            command_entries,
            "properties",
        ),
        "kernel": _section_payload(
            kernel_status,
            asdict(kernel) if kernel else {},
            command_entries,
            "kernel",
        ),
        "cpu": _section_payload(
            cpu_status,
            asdict(cpu) if cpu else {},
            command_entries,
            "cpu",
        ),
        "display": _section_payload(
            display_status,
            asdict(display) if display else {},
            command_entries,
            "display",
        ),
        "telephony": _section_payload(
            telephony_status,
            asdict(telephony) if telephony else {},
            command_entries,
            "telephony",
            source_command_ids={"properties.getprop"},
        ),
        "packages": _section_payload(
            packages_status,
            {name: asdict(package) for name, package in sorted(packages.items())},
            command_entries,
            "packages",
        ),
        "google_play_services": _section_payload(
            _gms_status(packages.get("com.google.android.gms"), packages_status),
            _gms_summary(packages.get("com.google.android.gms")),
            command_entries,
            "google_play_services",
            source_command_ids={
                entry["id"]
                for entry in command_entries
                if entry["section"] == "packages" and "com_google_android_gms" in entry["id"]
            },
        ),
        "magisk": _section_payload(
            magisk_status,
            asdict(magisk) if magisk else {},
            command_entries,
            "magisk",
        ),
        "runtime_markers": _section_payload(
            runtime_status,
            asdict(runtime) if runtime else {},
            command_entries,
            "runtime_markers",
        ),
        "camera": _section_payload(
            camera_status,
            asdict(camera) if camera else {},
            command_entries,
            "camera",
        ),
        "sensors": _section_payload(
            sensors_status,
            asdict(sensors) if sensors else {},
            command_entries,
            "sensors",
        ),
        "hal": _section_payload(
            hal_status,
            asdict(hal) if hal else {},
            command_entries,
            "hal",
            source_command_ids={"runtime.services", "properties.getprop"},
        ),
        "audio": _section_payload(
            audio_status,
            asdict(audio) if audio else {},
            command_entries,
            "audio",
        ),
        "battery": _section_payload(
            battery_status,
            asdict(battery) if battery else {},
            command_entries,
            "battery",
        ),
        "thermal": _section_payload(
            thermal_status,
            asdict(thermal) if thermal else {},
            command_entries,
            "thermal",
        ),
        "storage": _section_payload(
            storage_status,
            asdict(storage) if storage else {},
            command_entries,
            "storage",
            source_command_ids={"properties.getprop"},
        ),
    }
    for section_name, section in sections.items():
        section["profile_comparison_status"] = _profile_comparison_status(comparisons, section_name)
    report = {
        "schema_version": "4.0",
        "analyzer_version": __version__,
        "generated_at": _timestamp(),
        "bundle_schema_version": manifest["schema_version"],
        "source_bundle_digest": manifest["bundle_digest"],
        "profile": redact_text(profile.name) if profile else None,
        "profile_digest": _file_digest(profile_path) if profile_path else None,
        "sections": _redact_value(sections),
        "comparisons": [_redact_value(asdict(comparison)) for comparison in comparisons],
        "findings": [_redact_value(asdict(finding)) for finding in findings],
        "collection_issues": _collection_issues(command_entries),
        "summary": {
            "finding_count": len(findings),
            "collector_error_count": collector_errors,
            "profile_references_applied": profile is not None,
            "comparison_counts": _comparison_counts(comparisons),
            "section_statuses": {name: section["status"] for name, section in sections.items()},
        },
    }
    report_path = output_dir / "report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (output_dir / "report.md").write_text(
        render_markdown_report(report),
        encoding="utf-8",
        newline="\n",
    )
    (output_dir / "summary.txt").write_text(
        render_summary(report),
        encoding="utf-8",
        newline="\n",
    )
    return AnalysisOutcome(findings=findings, collector_errors=collector_errors, report_path=report_path)


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render compact observations and provenance without embedding raw dumps."""

    lines = [
        "# Android Device Audit Report",
        "",
        f"Generated: `{report['generated_at']}`",
        f"Bundle schema: `{report['bundle_schema_version']}`",
        f"Source bundle: `{report['source_bundle_digest']}`",
        f"Profile: `{report['profile'] or 'inventory only'}`",
        "",
        "## Summary",
        "",
        f"- Findings: **{report['summary']['finding_count']}**",
        f"- Collector errors: **{report['summary']['collector_error_count']}**",
        "- Aggregate consistency scores: not calculated",
        "",
    ]
    section_titles = (
        ("transport", "Transport"),
        ("properties", "Properties"),
        ("kernel", "Kernel"),
        ("cpu", "CPU / SoC"),
        ("display", "Display"),
        ("telephony", "Telephony"),
        ("packages", "Package Metadata"),
        ("google_play_services", "Google Play Services"),
        ("magisk", "Magisk Inventory"),
        ("runtime_markers", "Environment-Specific Markers"),
        ("camera", "Camera Inventory"),
        ("sensors", "Sensor Inventory"),
        ("hal", "HAL and Native Services"),
        ("audio", "Audio Inventory"),
        ("battery", "Battery and Charging Inventory"),
        ("thermal", "Thermal and Power Inventory"),
        ("storage", "Storage Inventory"),
    )
    for key, title in section_titles:
        _append_markdown_section(lines, title, report["sections"][key])
    lines.extend(["## Findings", ""])
    if not report["findings"]:
        lines.append("No profile-driven findings.")
    else:
        for finding in report["findings"]:
            lines.append(f"- **{finding['id']}** ({finding['severity']}): {finding['summary']}")
    lines.extend(["", "## Collection Errors and Permission Limits", ""])
    if not report["collection_issues"]:
        lines.append("No command-level collection issues were recorded.")
    else:
        for issue in report["collection_issues"]:
            lines.append(f"- `{issue['command']}`: `{issue['status']}`")
    lines.append("")
    return "\n".join(lines)


def render_summary(report: dict[str, Any]) -> str:
    """Render a plain-text summary suitable for scripts and terminals."""

    return (
        f"Findings: {report['summary']['finding_count']}\n"
        f"Collector errors: {report['summary']['collector_error_count']}\n"
        f"Profile: {report['profile'] or 'inventory only'}\n"
        f"Bundle schema: {report['bundle_schema_version']}\n"
    )


def _parse_transport(bundle_dir: Path, commands: dict[str, dict[str, Any]]) -> tuple[dict[str, str], str]:
    state_entry = commands.get("transport.state")
    data: dict[str, str] = {}
    for command_id, field in (
        ("transport.state", "device_state"),
        ("transport.id", "shell_identity"),
        ("transport.getenforce", "selinux_mode"),
    ):
        entry = commands.get(command_id)
        if entry and entry["status"] == "observed":
            data[field] = _read_stdout(bundle_dir, entry).strip()
    if not state_entry:
        return data, "not_evaluated"
    return data, "observed" if state_entry["status"] == "observed" else state_entry["status"]


def _parse_properties(bundle_dir: Path, commands: dict[str, dict[str, Any]]) -> tuple[dict[str, str], str]:
    entry = commands.get("properties.getprop")
    if not entry:
        return {}, "not_evaluated"
    if entry["status"] != "observed":
        return {}, entry["status"]
    properties = parse_getprop(_read_stdout(bundle_dir, entry))
    return properties, "observed" if properties else "parse_error"


def _parse_kernel(bundle_dir: Path, commands: dict[str, dict[str, Any]]) -> tuple[KernelInfo | None, str]:
    fallback_status = "not_evaluated"
    for command_id in ("kernel.uname", "kernel.osrelease", "kernel.proc_version"):
        entry = commands.get(command_id)
        if not entry:
            continue
        if entry["status"] != "observed":
            fallback_status = entry["status"]
            continue
        kernel = parse_kernel_info(_read_stdout(bundle_dir, entry))
        if kernel.release:
            return kernel, "observed"
        fallback_status = "parse_error"
    return None, fallback_status


def _parse_cpu(bundle_dir: Path, commands: dict[str, dict[str, Any]]) -> tuple[CpuTopology | None, str]:
    info_entry = commands.get("cpu.cpuinfo")
    count_entry = commands.get("cpu.online_count")
    if not info_entry:
        return None, "not_evaluated"
    if info_entry["status"] != "observed":
        return None, info_entry["status"]
    online_count = None
    if count_entry and count_entry["status"] == "observed":
        online_count = parse_online_cpu_count(_read_stdout(bundle_dir, count_entry))
    range_entry = commands.get("cpu.online_range")
    if online_count is None and range_entry and range_entry["status"] == "observed":
        online_count = parse_online_cpu_count(_read_stdout(bundle_dir, range_entry))
    topology = parse_cpuinfo(_read_stdout(bundle_dir, info_entry), online_cpu_count=online_count)
    return topology, "observed" if topology.clusters else "parse_error"


def _parse_display(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    collector_states: dict[str, str],
) -> tuple[DisplayInfo | None, str]:
    entries = _entries_by_prefix(commands, "display.")
    if not entries:
        return None, collector_states.get("display", "not_evaluated")
    density_text = _observed_stdout(bundle_dir, commands.get("display.wm_density"))
    forced_density = _observed_stdout(bundle_dir, commands.get("display.forced_density")).strip()
    if forced_density.isdigit() and "Override density" not in density_text:
        density_text = f"{density_text}\nOverride density: {forced_density}\n"
    display = parse_display_info(
        _observed_stdout(bundle_dir, commands.get("display.wm_size")),
        density_text,
        _observed_stdout(bundle_dir, commands.get("display.dumpsys")),
        _observed_stdout(bundle_dir, commands.get("display.window_displays")),
    )
    has_data = any(
        value not in (None, (), [])
        for value in asdict(display).values()
    )
    return display, _parsed_section_status(entries, has_data)


def _parse_telephony(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    properties: dict[str, str],
    collector_states: dict[str, str],
) -> tuple[TelephonyInfo | None, str]:
    entries = _entries_by_prefix(commands, "telephony.")
    telephony = parse_telephony_info(
        properties,
        _observed_stdout(bundle_dir, commands.get("telephony.registry")),
        _observed_stdout(bundle_dir, commands.get("telephony.isub")),
        _observed_stdout(bundle_dir, commands.get("telephony.telecom")),
    )
    data = asdict(telephony)
    has_data = any(value not in (None, (), {}, []) for value in data.values())
    if not entries and not has_data:
        return None, collector_states.get("telephony", "not_evaluated")
    return telephony, _parsed_section_status(entries, has_data) if entries else "observed"


def _parse_packages(
    bundle_dir: Path,
    command_entries: list[dict[str, Any]],
    collector_states: dict[str, str],
) -> tuple[dict[str, PackageInfo], str]:
    package_entries = [entry for entry in command_entries if entry["section"] == "packages"]
    if not package_entries:
        return {}, collector_states.get("packages", "not_evaluated")
    grouped: dict[str, dict[str, dict[str, Any]]] = {}
    for entry in package_entries:
        command = entry["command"]
        if not command:
            continue
        package_name = command[-1]
        if not isinstance(package_name, str) or package_name == "<redacted-serial>":
            continue
        kind = "path" if ".path" in entry["id"] else "dumpsys"
        grouped.setdefault(package_name, {})[kind] = entry
    packages: dict[str, PackageInfo] = {}
    for package_name, entries in grouped.items():
        path_entry = entries.get("path")
        dumpsys_entry = entries.get("dumpsys")
        packages[package_name] = parse_package_info(
            package_name,
            _read_optional_stdout(bundle_dir, path_entry),
            _read_optional_stdout(bundle_dir, dumpsys_entry),
            path_stderr=_read_optional_stderr(bundle_dir, path_entry),
            dumpsys_stderr=_read_optional_stderr(bundle_dir, dumpsys_entry),
        )
    has_data = any(package.installed is not None for package in packages.values())
    return packages, _parsed_section_status(package_entries, has_data)


def _parse_magisk(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    collector_states: dict[str, str],
) -> tuple[MagiskInfo | None, str]:
    relevant_ids = {
        "root.su_path",
        "root.id",
        "magisk.version",
        "magisk.version_code",
        "magisk.path",
        "magisk.settings",
        "magisk.modules",
        "magisk.cloud_property",
    }
    entries = [
        entry
        for command_id, entry in commands.items()
        if command_id in relevant_ids and entry["section"] == "magisk"
    ]
    if not entries:
        return None, collector_states.get("magisk", "not_evaluated")
    magisk = parse_magisk_info(
        _read_optional_stdout(bundle_dir, commands.get("root.su_path")),
        _read_optional_stdout(bundle_dir, commands.get("root.id")),
        _read_optional_stdout(bundle_dir, commands.get("magisk.version")),
        _read_optional_stdout(bundle_dir, commands.get("magisk.version_code")),
        _read_optional_stdout(bundle_dir, commands.get("magisk.path")),
        _read_optional_stdout(bundle_dir, commands.get("magisk.settings")),
        _read_optional_stdout(bundle_dir, commands.get("magisk.modules")),
        _read_optional_stdout(bundle_dir, commands.get("magisk.cloud_property")),
    )
    return magisk, _parsed_section_status(entries, any(entry["status"] == "observed" for entry in entries))


def _parse_runtime(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    collector_states: dict[str, str],
) -> tuple[RuntimeMarkers | None, str]:
    entries = _entries_by_prefix(commands, "runtime.")
    if not entries:
        return None, collector_states.get("runtime_markers", "not_evaluated")
    runtime = parse_runtime_markers(
        _read_optional_stdout(bundle_dir, commands.get("runtime.mount")),
        _read_optional_stdout(bundle_dir, commands.get("runtime.proc_mounts")),
        _read_optional_stdout(bundle_dir, commands.get("runtime.processes")),
        _read_optional_stdout(bundle_dir, commands.get("runtime.services")),
        _read_optional_stdout(bundle_dir, commands.get("runtime.debug_ramdisk")),
        _read_optional_stdout(bundle_dir, commands.get("runtime.data_adb")),
        _read_optional_stdout(bundle_dir, commands.get("runtime.data_adb_modules")),
        _read_optional_stdout(bundle_dir, commands.get("runtime.data_adb_magisk")),
    )
    return runtime, _parsed_section_status(entries, any(entry["status"] == "observed" for entry in entries))

def _parse_camera(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    collector_states: dict[str, str],
) -> tuple[CameraInventory | None, str]:
    entries = _entries_by_prefix(commands, "camera.")
    if not entries:
        return None, collector_states.get("camera", "not_evaluated")
    camera = parse_camera_info(
        _observed_stdout(bundle_dir, commands.get("camera.media_camera")),
        _observed_stdout(bundle_dir, commands.get("camera.cmd_list")),
        _observed_stdout(bundle_dir, commands.get("camera.cmd_dump")),
    )
    has_data = camera.camera_count > 0 or bool(camera.parse_warnings) or camera.service_status is not None
    return camera, _parsed_section_status(entries, has_data)

def _parse_sensors(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    collector_states: dict[str, str],
) -> tuple[SensorInventory | None, str]:
    entries = _entries_by_prefix(commands, "sensors.")
    if not entries:
        return None, collector_states.get("sensors", "not_evaluated")
    sensors = parse_sensor_info(_observed_stdout(bundle_dir, commands.get("sensors.sensorservice")))
    has_data = sensors.sensor_count > 0 or bool(sensors.parse_warnings) or sensors.service_status is not None
    return sensors, _parsed_section_status(entries, has_data)

def _parse_hal(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    properties: dict[str, str],
    collector_states: dict[str, str],
) -> tuple[HalInventory | None, str]:
    entries = _entries_by_prefix(commands, "hal.")
    if not entries:
        return None, collector_states.get("hal", "not_evaluated")
    hal = parse_hal_info(
        _observed_stdout(bundle_dir, commands.get("hal.lshal")),
        _observed_stdout(bundle_dir, commands.get("hal.lshal_interfaces")),
        _observed_stdout(bundle_dir, commands.get("hal.dumpsys_services")),
        _observed_stdout(bundle_dir, commands.get("runtime.services")),
        properties,
    )
    has_data = hal.hal_count > 0 or hal.binder_service_count > 0 or hal.dumpsys_service_count > 0 or bool(hal.hal_properties)
    return hal, _parsed_section_status(entries, has_data)


def _parse_audio(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    collector_states: dict[str, str],
) -> tuple[AudioInventory | None, str]:
    entries = _entries_by_prefix(commands, "audio.")
    if not entries:
        return None, collector_states.get("audio", "not_evaluated")
    audio = parse_audio_info(
        _observed_stdout(bundle_dir, commands.get("audio.dumpsys_audio")),
        _observed_stdout(bundle_dir, commands.get("audio.audio_flinger")),
        _observed_stdout(bundle_dir, commands.get("audio.audio_policy")),
        _observed_stdout(bundle_dir, commands.get("audio.policy_ports")),
        _observed_stdout(bundle_dir, commands.get("audio.policy_patches")),
    )
    has_data = bool(audio.output_devices or audio.input_devices or audio.parse_warnings) or audio.service_status is not None
    return audio, _parsed_section_status(entries, has_data)


def _parse_battery(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    collector_states: dict[str, str],
) -> tuple[BatteryInventory | None, str]:
    entries = _entries_by_prefix(commands, "battery.")
    if not entries:
        return None, collector_states.get("battery", "not_evaluated")
    command_values = {
        name: _observed_stdout(bundle_dir, commands.get(command_id))
        for name, command_id in (
            ("status", "battery.cmd_status"),
            ("health", "battery.cmd_health"),
            ("level", "battery.cmd_level"),
            ("plugged", "battery.cmd_plugged"),
            ("current now", "battery.cmd_current"),
            ("temperature", "battery.cmd_temperature"),
            ("charge counter", "battery.cmd_counter"),
            ("charging", "battery.cmd_charging_status"),
        )
    }
    for key, unit in (
        ("current now", "uA"),
        ("temperature", "tenths C"),
        ("charge counter", "uAh"),
    ):
        value = command_values[key].strip()
        if value and value.lstrip("-").isdigit():
            command_values[key] = f"{value} {unit}"
    battery = parse_battery_info(
        _observed_stdout(bundle_dir, commands.get("battery.dumpsys_battery")),
        _observed_stdout(bundle_dir, commands.get("battery.properties")),
        command_values,
    )
    has_data = any(value is not None for value in asdict(battery).values() if not isinstance(value, tuple))
    return battery, _parsed_section_status(entries, has_data)


def _parse_thermal(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    collector_states: dict[str, str],
) -> tuple[ThermalInventory | None, str]:
    entries = _entries_by_prefix(commands, "thermal.")
    if not entries:
        return None, collector_states.get("thermal", "not_evaluated")
    thermal = parse_thermal_info(
        _observed_stdout(bundle_dir, commands.get("thermal.service")),
        _observed_stdout(bundle_dir, commands.get("thermal.power")),
        _observed_stdout(bundle_dir, commands.get("thermal.deviceidle")),
        _observed_stdout(bundle_dir, commands.get("thermal.cmd_dump")),
        _observed_stdout(bundle_dir, commands.get("thermal.power_mode")),
        _observed_stdout(bundle_dir, commands.get("thermal.fixed_performance_mode")),
    )
    has_data = bool(thermal.temperature_sensors or thermal.cooling_devices or thermal.parse_warnings) or any(
        value is not None
        for key, value in asdict(thermal).items()
        if key not in {"temperature_sensors", "cooling_devices", "parse_warnings"}
    )
    return thermal, _parsed_section_status(entries, has_data)


def _parse_storage(
    bundle_dir: Path,
    commands: dict[str, dict[str, Any]],
    properties: dict[str, str],
    collector_states: dict[str, str],
) -> tuple[StorageInventory | None, str]:
    entries = _entries_by_prefix(commands, "storage.")
    if not entries:
        return None, collector_states.get("storage", "not_evaluated")
    storage = parse_storage_info(
        _observed_stdout(bundle_dir, commands.get("storage.df_k")),
        _observed_stdout(bundle_dir, commands.get("storage.mount")),
        _observed_stdout(bundle_dir, commands.get("storage.proc_mounts")),
        _observed_stdout(bundle_dir, commands.get("storage.proc_filesystems")),
        _observed_stdout(bundle_dir, commands.get("storage.proc_partitions")),
        _observed_stdout(bundle_dir, commands.get("storage.dumpsys_mount")),
        _observed_stdout(bundle_dir, commands.get("storage.volumes")),
        _observed_stdout(bundle_dir, commands.get("storage.disks")),
        _observed_stdout(bundle_dir, commands.get("storage.primary_uuid")),
        properties,
    )
    has_data = bool(storage.mounts or storage.volumes or storage.partitions or storage.supported_filesystems or storage.parse_warnings)
    return storage, _parsed_section_status(entries, has_data)


def _section_payload(
    status: str,
    data: dict[str, Any],
    commands: list[dict[str, Any]],
    section: str,
    source_command_ids: set[str] | None = None,
) -> dict[str, Any]:
    section_commands = [
        entry
        for entry in commands
        if entry["section"] == section or (source_command_ids and entry["id"] in source_command_ids)
    ]
    observed_fields, not_evaluated_fields = _field_states(data)
    return {
        "status": status,
        "data": data,
        "observed_fields": observed_fields,
        "not_evaluated_fields": not_evaluated_fields,
        "permission_limits": [entry["id"] for entry in section_commands if entry["status"] == "permission_denied"],
        "timeouts": [entry["id"] for entry in section_commands if entry["status"] == "timeout"],
        "parse_errors": [section] if status == "parse_error" else [],
        "unsupported_commands": [entry["id"] for entry in section_commands if entry["status"] == "unsupported"],
        "source_commands": [entry["id"] for entry in section_commands],
        "commands": {entry["id"]: entry["status"] for entry in section_commands},
    }


def _field_states(data: dict[str, Any], prefix: str = "") -> tuple[list[str], list[str]]:
    observed: list[str] = []
    not_evaluated: list[str] = []
    for key, value in data.items():
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            child_observed, child_not_evaluated = _field_states(value, name)
            observed.extend(child_observed)
            not_evaluated.extend(child_not_evaluated)
        elif value is None:
            not_evaluated.append(name)
        else:
            observed.append(name)
    return observed, not_evaluated


def _append_markdown_section(lines: list[str], title: str, section: dict[str, Any]) -> None:
    lines.extend(
        [
            f"## {title}",
            "",
            f"- Status: `{section['status']}`",
            f"- Observed fields: {_markdown_list(section['observed_fields'])}",
            f"- Not evaluated fields: {_markdown_list(section['not_evaluated_fields'])}",
            f"- Permission limits: {_markdown_list(section['permission_limits'])}",
            f"- Timeouts: {_markdown_list(section['timeouts'])}",
            f"- Parse errors: {_markdown_list(section['parse_errors'])}",
            f"- Unsupported commands: {_markdown_list(section['unsupported_commands'])}",
            f"- Profile comparison: `{section['profile_comparison_status']}`",
            f"- Source commands: {_markdown_list(section['source_commands'])}",
        ]
    )
    if section["data"]:
        lines.extend(["", "Observed summary:"])
        for key, value in section["data"].items():
            lines.append(f"- `{key}`: `{_json_inline(value)}`")
    lines.append("")


def _gms_summary(package: PackageInfo | None) -> dict[str, Any]:
    if package is None:
        return {}
    data = asdict(package)
    included = (
        "installed",
        "version_name",
        "version_code",
        "target_sdk",
        "installer_package_name",
        "code_paths",
        "enabled",
        "stopped",
        "suspended",
        "system_app",
        "privileged_app",
        "signing_certificate_digests",
    )
    return {key: data[key] for key in included}


def _gms_status(package: PackageInfo | None, packages_status: str) -> str:
    if package is None:
        return "not_evaluated" if packages_status == "not_evaluated" else packages_status
    return "observed" if package.installed is not None else packages_status


def _entries_by_prefix(commands: dict[str, dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    return [entry for command_id, entry in commands.items() if command_id.startswith(prefix)]


def _parsed_section_status(entries: list[dict[str, Any]], has_data: bool) -> str:
    if has_data:
        return "observed"
    statuses = [entry["status"] for entry in entries]
    for status in ("timeout", "permission_denied", "unsupported", "unavailable"):
        if status in statuses and "observed" not in statuses:
            return status
    return "parse_error" if "observed" in statuses else statuses[0] if statuses else "not_evaluated"

def _profile_comparison_status(comparisons: tuple[Comparison, ...], category: str) -> str:
    relevant = [comparison.status for comparison in comparisons if comparison.category == category]
    if not relevant or all(status == "not_evaluated" for status in relevant):
        return "not_evaluated"
    if "mismatched" in relevant:
        return "mismatched"
    return "matched" if all(status == "matched" for status in relevant) else "not_evaluated"


def _observed_stdout(bundle_dir: Path, entry: dict[str, Any] | None) -> str:
    if not entry or entry["status"] != "observed":
        return ""
    return _read_stdout(bundle_dir, entry)


def _read_optional_stdout(bundle_dir: Path, entry: dict[str, Any] | None) -> str:
    return _read_stdout(bundle_dir, entry) if entry else ""


def _read_optional_stderr(bundle_dir: Path, entry: dict[str, Any] | None) -> str:
    return _read_stderr(bundle_dir, entry) if entry else ""


def _read_stdout(bundle_dir: Path, entry: dict[str, Any]) -> str:
    return (bundle_dir / entry["stdout_path"]).read_text(encoding="utf-8")


def _read_stderr(bundle_dir: Path, entry: dict[str, Any]) -> str:
    return (bundle_dir / entry["stderr_path"]).read_text(encoding="utf-8")


def _file_digest(path: Path | None) -> str | None:
    if path is None:
        return None
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _comparison_counts(comparisons: tuple[Comparison, ...]) -> dict[str, int]:
    counts = {"matched": 0, "mismatched": 0, "not_evaluated": 0}
    for comparison in comparisons:
        counts[comparison.status] = counts.get(comparison.status, 0) + 1
    return counts


def _collection_issues(commands: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {"command": entry["id"], "status": entry["status"]}
        for entry in commands
        if entry["status"] != "observed"
    ]


def _markdown_list(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "none"


def _json_inline(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    return value


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
