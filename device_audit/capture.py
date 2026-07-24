"""Read-only ADB evidence capture orchestrated through collector plugins."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from device_audit.adb import ADBClient, DeviceSelectionError, choose_serial, list_devices, parse_devices
from device_audit.bundle import command_status, write_evidence_bundle
from device_audit.collector_api import CollectionRequest, CollectorRegistry, CommandSpec
from device_audit.collectors import (
    AUDIO_COMMANDS,
    BATTERY_COMMANDS,
    BUILTIN_COLLECTORS,
    CAMERA_COMMANDS,
    DEFAULT_PACKAGES,
    DISPLAY_COMMANDS,
    GRAPHICS_COMMANDS,
    HAL_COMMANDS,
    INPUT_COMMANDS,
    MAGISK_COMMANDS,
    MEMORY_COMMANDS,
    NETWORK_COMMANDS,
    PHASE_ONE_COMMANDS,
    ROOT_RUNTIME_COMMANDS,
    RUNTIME_COMMANDS,
    SENSOR_COMMANDS,
    STORAGE_COMMANDS,
    TELEPHONY_COMMANDS,
    THERMAL_COMMANDS,
    normalize_packages,
)
from device_audit.models import EvidenceCommand


@dataclass(frozen=True)
class CaptureOutcome:
    """The persisted result of one live evidence collection."""

    bundle_path: Path
    collector_errors: int


@dataclass(frozen=True)
class CaptureOptions:
    """Optional Phase 2-5 collectors selected for one capture."""

    skip_display: bool = False
    skip_telephony: bool = False
    skip_packages: bool = False
    skip_magisk: bool = False
    skip_runtime_markers: bool = False
    skip_camera: bool = False
    skip_sensors: bool = False
    skip_hal: bool = False
    skip_audio: bool = False
    skip_battery: bool = False
    skip_thermal: bool = False
    skip_storage: bool = False
    skip_network: bool = False
    skip_graphics: bool = False
    skip_input: bool = False
    skip_memory: bool = False
    packages: tuple[str, ...] = ()


DEFAULT_COLLECTOR_REGISTRY = CollectorRegistry(BUILTIN_COLLECTORS)


def capture_evidence(
    adb_path: Path,
    requested_serial: str | None,
    output_dir: Path,
    timeout_seconds: int,
    options: CaptureOptions | None = None,
    collector_registry: CollectorRegistry | None = None,
) -> CaptureOutcome:
    """Collect enabled evidence sections and persist a redacted bundle."""

    options = options or CaptureOptions()
    request = _collection_request(options, timeout_seconds)
    devices = []
    devices_result = None
    if requested_serial is None:
        devices_result = list_devices(adb_path, timeout_seconds=timeout_seconds)
        if devices_result.exit_code != 0 or devices_result.timed_out:
            raise DeviceSelectionError("unable to obtain ready device list from adb")
        devices = parse_devices(devices_result.stdout)
        serial = choose_serial(devices, requested_serial)
    else:
        serial = requested_serial
    client = ADBClient(adb_path=adb_path, serial=serial, timeout_seconds=timeout_seconds)
    state_result = client.get_state()
    if state_result.exit_code != 0 or state_result.timed_out or state_result.stdout.strip() != "device":
        raise DeviceSelectionError("selected device is no longer ready")

    collection = (collector_registry or DEFAULT_COLLECTOR_REGISTRY).collect(client, request)
    commands = []
    if devices_result is not None:
        commands.append(EvidenceCommand(id="transport.devices", section="transport", result=devices_result))
    commands.extend(
        [
            EvidenceCommand(id="transport.state", section="transport", result=state_result),
            *collection.commands,
        ]
    )
    collector_states = {
        "display": _collector_state(commands, "display", options.skip_display),
        "telephony": _collector_state(commands, "telephony", options.skip_telephony),
        "packages": _collector_state(commands, "packages", options.skip_packages),
        "magisk": _collector_state(commands, "magisk", options.skip_magisk),
        "runtime_markers": _collector_state(
            commands,
            "runtime_markers",
            options.skip_runtime_markers,
        ),
        "camera": _collector_state(commands, "camera", options.skip_camera),
        "sensors": _collector_state(commands, "sensors", options.skip_sensors),
        "hal": _collector_state(commands, "hal", options.skip_hal),
        "audio": _collector_state(commands, "audio", options.skip_audio),
        "battery": _collector_state(commands, "battery", options.skip_battery),
        "thermal": _collector_state(commands, "thermal", options.skip_thermal),
        "storage": _collector_state(commands, "storage", options.skip_storage),
        "network": _collector_state(commands, "network", options.skip_network),
        "graphics": _collector_state(commands, "graphics", options.skip_graphics),
        "input": _collector_state(commands, "input", options.skip_input),
        "memory": _collector_state(commands, "memory", options.skip_memory),
    }
    bundle_path = write_evidence_bundle(
        output_dir=output_dir,
        serial=serial,
        commands=commands,
        additional_sensitive_values=(device.serial for device in devices),
        collector_states=collector_states,
        schema_version="5.0",
    )
    collector_errors = sum(
        (command.status_override or command_status(command.result)) != "observed" for command in commands
    )
    return CaptureOutcome(bundle_path=bundle_path, collector_errors=collector_errors)


def _collection_request(options: CaptureOptions, timeout_seconds: int) -> CollectionRequest:
    skipped_sections = frozenset(
        section
        for section, skipped in (
            ("display", options.skip_display),
            ("telephony", options.skip_telephony),
            ("packages", options.skip_packages),
            ("magisk", options.skip_magisk),
            ("runtime_markers", options.skip_runtime_markers),
            ("camera", options.skip_camera),
            ("sensors", options.skip_sensors),
            ("hal", options.skip_hal),
            ("audio", options.skip_audio),
            ("battery", options.skip_battery),
            ("thermal", options.skip_thermal),
            ("storage", options.skip_storage),
            ("network", options.skip_network),
            ("graphics", options.skip_graphics),
            ("input", options.skip_input),
            ("memory", options.skip_memory),
        )
        if skipped
    )
    package_names = normalize_packages(options.packages) if not options.skip_packages else ()
    return CollectionRequest(
        skipped_sections=skipped_sections,
        packages=package_names,
        timeout_seconds=timeout_seconds,
    )


def _collector_state(commands: list[EvidenceCommand], section: str, skipped: bool) -> str:
    if skipped:
        return "not_evaluated"
    statuses = [
        command.status_override or command_status(command.result)
        for command in commands
        if command.section == section
    ]
    if not statuses:
        return "unavailable"
    if any(status == "observed" for status in statuses):
        return "observed"
    for status in ("timeout", "permission_denied", "unsupported", "unavailable"):
        if status in statuses:
            return status
    return statuses[0]


__all__ = [
    "AUDIO_COMMANDS",
    "BATTERY_COMMANDS",
    "CaptureOptions",
    "CaptureOutcome",
    "CommandSpec",
    "DEFAULT_COLLECTOR_REGISTRY",
    "DEFAULT_PACKAGES",
    "DISPLAY_COMMANDS",
    "CAMERA_COMMANDS",
    "GRAPHICS_COMMANDS",
    "HAL_COMMANDS",
    "INPUT_COMMANDS",
    "MAGISK_COMMANDS",
    "MEMORY_COMMANDS",
    "NETWORK_COMMANDS",
    "PHASE_ONE_COMMANDS",
    "ROOT_RUNTIME_COMMANDS",
    "RUNTIME_COMMANDS",
    "SENSOR_COMMANDS",
    "STORAGE_COMMANDS",
    "TELEPHONY_COMMANDS",
    "THERMAL_COMMANDS",
    "capture_evidence",
    "normalize_packages",
]
