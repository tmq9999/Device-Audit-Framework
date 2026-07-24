"""Versioned expected-profile loading and validation."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from device_audit.models import CpuCluster, CpuTopology, ExpectedProfile, PackageExpectation


_PACKAGE_PATTERN = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
_DISPLAY_SIZE_PATTERN = re.compile(r"^\d+x\d+$")


class ProfileValidationError(ValueError):
    """Raised when an expected profile cannot be used safely."""


def load_profile(path: Path) -> ExpectedProfile:
    """Load and validate an expected profile JSON document."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ProfileValidationError(f"unable to read profile: {error}") from error
    except json.JSONDecodeError as error:
        raise ProfileValidationError(f"invalid JSON profile: {error}") from error
    return profile_from_mapping(payload)


def profile_from_mapping(payload: Any) -> ExpectedProfile:
    """Validate a decoded profile mapping and construct an expected profile."""

    if not isinstance(payload, dict):
        raise ProfileValidationError("profile root must be an object")
    schema_version = _required_string(payload, "schema_version")
    if not schema_version.startswith(("1.", "2.", "3.", "4.", "5.")):
        raise ProfileValidationError(f"unsupported profile schema_version: {schema_version}")
    name = _required_string(payload, "name")
    identity = _string_mapping(payload.get("identity", {}), "identity")
    build = _string_mapping(payload.get("build", {}), "build")

    kernel = payload.get("kernel", {})
    if not isinstance(kernel, dict):
        raise ProfileValidationError("kernel must be an object")
    allowed_lineages_value = kernel.get("allowed_lineages", [])
    if not isinstance(allowed_lineages_value, list) or not all(
        isinstance(value, str) and value for value in allowed_lineages_value
    ):
        raise ProfileValidationError("kernel.allowed_lineages must be a list of non-empty strings")

    native_cpu = payload.get("native_cpu", {})
    if not isinstance(native_cpu, dict):
        raise ProfileValidationError("native_cpu must be an object")
    topologies_value = native_cpu.get("allowed_topologies", [])
    if not isinstance(topologies_value, list):
        raise ProfileValidationError("native_cpu.allowed_topologies must be a list")
    topologies = tuple(_parse_topology(value) for value in topologies_value)

    display = payload.get("display", {})
    if not isinstance(display, dict):
        raise ProfileValidationError("display must be an object")
    display_sizes = _string_list(display.get("allowed_physical_sizes", []), "display.allowed_physical_sizes")
    if any(not _DISPLAY_SIZE_PATTERN.fullmatch(value) for value in display_sizes):
        raise ProfileValidationError("display.allowed_physical_sizes must contain WIDTHxHEIGHT values")
    density_ranges = _integer_ranges(
        display.get("allowed_density_ranges", []),
        "display.allowed_density_ranges",
    )
    refresh_rates_value = display.get("allowed_refresh_rates", [])
    if not isinstance(refresh_rates_value, list) or any(
        isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0
        for value in refresh_rates_value
    ):
        raise ProfileValidationError("display.allowed_refresh_rates must be positive numbers")

    telephony = payload.get("telephony", {})
    if not isinstance(telephony, dict):
        raise ProfileValidationError("telephony must be an object")
    operator_numeric = _string_list(
        telephony.get("allowed_operator_numeric", []),
        "telephony.allowed_operator_numeric",
    )
    country_iso = tuple(
        value.lower()
        for value in _string_list(
            telephony.get("allowed_country_iso", []),
            "telephony.allowed_country_iso",
        )
    )
    network_types = _string_list(
        telephony.get("allowed_network_types", []),
        "telephony.allowed_network_types",
    )
    ril_vendors = _string_list(
        telephony.get("allowed_ril_vendors", []),
        "telephony.allowed_ril_vendors",
    )
    baseband_patterns = _string_list(
        telephony.get("allowed_baseband_patterns", []),
        "telephony.allowed_baseband_patterns",
    )
    for pattern in baseband_patterns:
        try:
            re.compile(pattern)
        except re.error as error:
            raise ProfileValidationError(
                f"telephony.allowed_baseband_patterns contains invalid regex: {error}"
            ) from error

    package_expectations = _parse_package_expectations(payload.get("packages", {}))

    camera = payload.get("camera", {})
    if not isinstance(camera, dict):
        raise ProfileValidationError("camera must be an object")
    camera_minimum_count = _optional_nonnegative_int(
        camera.get("minimum_camera_count"),
        "camera.minimum_camera_count",
    )
    camera_required_facing = tuple(
        value.lower()
        for value in _string_list(camera.get("required_facing", []), "camera.required_facing")
    )
    if any(
        value not in {"front", "back", "external", "unknown"}
        for value in camera_required_facing
    ):
        raise ProfileValidationError("camera.required_facing contains an invalid facing")
    camera_required_ids = _string_list(
        camera.get("required_camera_ids", []),
        "camera.required_camera_ids",
    )
    camera_allowed_levels = tuple(
        value.upper()
        for value in _string_list(
            camera.get("allowed_hardware_levels", []),
            "camera.allowed_hardware_levels",
        )
    )
    if any(
        value not in {"LEGACY", "LIMITED", "FULL", "LEVEL_3", "EXTERNAL", "UNKNOWN"}
        for value in camera_allowed_levels
    ):
        raise ProfileValidationError("camera.allowed_hardware_levels contains an invalid level")
    camera_required_capabilities = tuple(
        value.upper()
        for value in _string_list(
            camera.get("required_capabilities", []),
            "camera.required_capabilities",
        )
    )

    sensors = payload.get("sensors", {})
    if not isinstance(sensors, dict):
        raise ProfileValidationError("sensors must be an object")
    sensors_minimum_count = _optional_nonnegative_int(
        sensors.get("minimum_sensor_count"),
        "sensors.minimum_sensor_count",
    )
    sensors_required_types = _string_list(
        sensors.get("required_types", []),
        "sensors.required_types",
    )
    sensors_allowed_vendors = _string_list(
        sensors.get("allowed_vendors", []),
        "sensors.allowed_vendors",
    )

    hal = payload.get("hal", {})
    if not isinstance(hal, dict):
        raise ProfileValidationError("hal must be an object")
    hal_required_interfaces = _string_list(
        hal.get("required_interfaces", []),
        "hal.required_interfaces",
    )
    hal_required_families = _string_list(
        hal.get("required_families", []),
        "hal.required_families",
    )
    hal_allowed_transports = tuple(
        value.lower()
        for value in _string_list(
            hal.get("allowed_transports", []),
            "hal.allowed_transports",
        )
    )
    if any(
        value not in {"hwbinder", "binder", "vndbinder", "passthrough", "unknown"}
        for value in hal_allowed_transports
    ):
        raise ProfileValidationError("hal.allowed_transports contains an invalid transport")

    audio = payload.get("audio", {})
    if not isinstance(audio, dict):
        raise ProfileValidationError("audio must be an object")
    audio_minimum_output = _optional_nonnegative_int(
        audio.get("minimum_output_device_count"), "audio.minimum_output_device_count"
    )
    audio_minimum_input = _optional_nonnegative_int(
        audio.get("minimum_input_device_count"), "audio.minimum_input_device_count"
    )
    audio_output_types = _string_list(
        audio.get("required_output_device_types", []), "audio.required_output_device_types"
    )
    audio_input_types = _string_list(
        audio.get("required_input_device_types", []), "audio.required_input_device_types"
    )
    audio_formats = _string_list(audio.get("required_output_formats", []), "audio.required_output_formats")
    audio_rates = _positive_integer_list(audio.get("required_sample_rates", []), "audio.required_sample_rates")
    audio_require_service = _optional_bool(audio.get("require_audio_service_available"), "audio.require_audio_service_available")
    audio_require_policy = _optional_bool(audio.get("require_audio_policy_available"), "audio.require_audio_policy_available")

    battery = payload.get("battery", {})
    if not isinstance(battery, dict):
        raise ProfileValidationError("battery must be an object")
    battery_require_present = _optional_bool(battery.get("require_present"), "battery.require_present")
    battery_health = tuple(value.upper() for value in _string_list(battery.get("allowed_health", []), "battery.allowed_health"))
    if any(value not in {"UNKNOWN", "GOOD", "OVERHEAT", "DEAD", "OVER_VOLTAGE", "UNSPECIFIED_FAILURE", "COLD"} for value in battery_health):
        raise ProfileValidationError("battery.allowed_health contains an invalid health")
    battery_plugged = tuple(value.upper() for value in _string_list(battery.get("allowed_plugged_sources", []), "battery.allowed_plugged_sources"))
    if any(value not in {"NONE", "AC", "USB", "WIRELESS", "DOCK", "MULTIPLE", "UNKNOWN"} for value in battery_plugged):
        raise ProfileValidationError("battery.allowed_plugged_sources contains an invalid source")
    battery_minimum_level = _optional_bounded_int(battery.get("minimum_level_percent"), "battery.minimum_level_percent", 0, 100)
    battery_maximum_temperature = _optional_nonnegative_int(
        battery.get("maximum_temperature_tenths_c"), "battery.maximum_temperature_tenths_c"
    )
    battery_require_service = _optional_bool(
        battery.get("require_property_service_available"), "battery.require_property_service_available"
    )

    thermal = payload.get("thermal", {})
    if not isinstance(thermal, dict):
        raise ProfileValidationError("thermal must be an object")
    thermal_require_service = _optional_bool(
        thermal.get("require_thermal_service_available"), "thermal.require_thermal_service_available"
    )
    thermal_required_types = tuple(value.upper() for value in _string_list(thermal.get("required_sensor_types", []), "thermal.required_sensor_types"))
    if any(value not in {"CPU", "GPU", "BATTERY", "SKIN", "USB_PORT", "POWER_AMPLIFIER", "BCL_VOLTAGE", "BCL_CURRENT", "BCL_PERCENTAGE", "NPU", "MODEM", "SOC", "AMBIENT", "UNKNOWN"} for value in thermal_required_types):
        raise ProfileValidationError("thermal.required_sensor_types contains an invalid type")
    thermal_severity = tuple(value.upper() for value in _string_list(thermal.get("allowed_current_severity", []), "thermal.allowed_current_severity"))
    if any(value not in {"NONE", "LIGHT", "MODERATE", "SEVERE", "CRITICAL", "EMERGENCY", "SHUTDOWN", "UNKNOWN"} for value in thermal_severity):
        raise ProfileValidationError("thermal.allowed_current_severity contains an invalid severity")
    thermal_maximum = _float_mapping(thermal.get("maximum_sensor_temperature_c", {}), "thermal.maximum_sensor_temperature_c")
    thermal_require_power = _optional_bool(
        thermal.get("require_power_service_available"), "thermal.require_power_service_available"
    )
    thermal_wakefulness = tuple(value.upper() for value in _string_list(thermal.get("allowed_wakefulness", []), "thermal.allowed_wakefulness"))
    if any(value not in {"AWAKE", "ASLEEP", "DREAMING", "DOZING", "UNKNOWN"} for value in thermal_wakefulness):
        raise ProfileValidationError("thermal.allowed_wakefulness contains an invalid state")

    storage = payload.get("storage", {})
    if not isinstance(storage, dict):
        raise ProfileValidationError("storage must be an object")
    storage_filesystems = _string_list(storage.get("required_filesystem_types", []), "storage.required_filesystem_types")
    storage_mount_points = _string_list(storage.get("required_mount_points", []), "storage.required_mount_points")
    storage_require_rw = _optional_bool(storage.get("require_data_mount_read_write"), "storage.require_data_mount_read_write")
    storage_minimum_available = _optional_nonnegative_int(storage.get("minimum_data_available_kb"), "storage.minimum_data_available_kb")
    storage_volume_types = tuple(value.upper() for value in _string_list(storage.get("allowed_volume_types", []), "storage.allowed_volume_types"))
    if any(value not in {"PUBLIC", "PRIVATE", "EMULATED", "STUB", "ASEC", "OBB", "UNKNOWN"} for value in storage_volume_types):
        raise ProfileValidationError("storage.allowed_volume_types contains an invalid volume type")
    storage_require_service = _optional_bool(storage.get("require_mount_service_available"), "storage.require_mount_service_available")

    network = payload.get("network", {})
    if not isinstance(network, dict):
        raise ProfileValidationError("network must be an object")
    network_interfaces = _string_list(network.get("required_interfaces", []), "network.required_interfaces")
    network_transports = tuple(
        value.upper()
        for value in _string_list(network.get("allowed_transport_types", []), "network.allowed_transport_types")
    )
    if any(
        value not in {"CELLULAR", "WIFI", "BLUETOOTH", "ETHERNET", "VPN", "WIFI_AWARE", "LOWPAN", "USB", "UNKNOWN"}
        for value in network_transports
    ):
        raise ProfileValidationError("network.allowed_transport_types contains an invalid transport")
    network_require_service = _optional_bool(
        network.get("require_connectivity_service_available"), "network.require_connectivity_service_available"
    )

    graphics = payload.get("graphics", {})
    if not isinstance(graphics, dict):
        raise ProfileValidationError("graphics must be an object")
    graphics_vendors = _string_list(graphics.get("allowed_gles_vendors", []), "graphics.allowed_gles_vendors")
    graphics_renderer_patterns = _string_list(
        graphics.get("allowed_gles_renderer_patterns", []), "graphics.allowed_gles_renderer_patterns"
    )
    for pattern in graphics_renderer_patterns:
        try:
            re.compile(pattern)
        except re.error as error:
            raise ProfileValidationError(
                f"graphics.allowed_gles_renderer_patterns contains invalid regex: {error}"
            ) from error
    graphics_require_service = _optional_bool(
        graphics.get("require_surface_flinger_available"), "graphics.require_surface_flinger_available"
    )

    input_section = payload.get("input", {})
    if not isinstance(input_section, dict):
        raise ProfileValidationError("input must be an object")
    input_minimum_devices = _optional_nonnegative_int(
        input_section.get("minimum_device_count"), "input.minimum_device_count"
    )
    input_required_classes = tuple(
        value.upper()
        for value in _string_list(input_section.get("required_device_classes", []), "input.required_device_classes")
    )
    if any(
        value not in {"TOUCHSCREEN", "KEYBOARD", "MOUSE", "GAMEPAD", "BUTTONS", "ROTARY_ENCODER", "SWITCH", "VIBRATOR", "UNKNOWN"}
        for value in input_required_classes
    ):
        raise ProfileValidationError("input.required_device_classes contains an invalid class")

    memory = payload.get("memory", {})
    if not isinstance(memory, dict):
        raise ProfileValidationError("memory must be an object")
    memory_minimum_total = _optional_nonnegative_int(memory.get("minimum_total_kb"), "memory.minimum_total_kb")
    memory_maximum_total = _optional_nonnegative_int(memory.get("maximum_total_kb"), "memory.maximum_total_kb")
    if (
        memory_minimum_total is not None
        and memory_maximum_total is not None
        and memory_minimum_total > memory_maximum_total
    ):
        raise ProfileValidationError("memory.minimum_total_kb must not exceed memory.maximum_total_kb")
    memory_require_low_ram = _optional_bool(memory.get("require_low_ram_flag"), "memory.require_low_ram_flag")

    return ExpectedProfile(
        schema_version=schema_version,
        name=name,
        identity=identity,
        build=build,
        kernel_allowed_lineages=tuple(allowed_lineages_value),
        allowed_cpu_topologies=topologies,
        display_allowed_physical_sizes=display_sizes,
        display_allowed_density_ranges=density_ranges,
        display_allowed_refresh_rates=tuple(float(value) for value in refresh_rates_value),
        telephony_allowed_operator_numeric=operator_numeric,
        telephony_allowed_country_iso=country_iso,
        telephony_allowed_network_types=network_types,
        telephony_allowed_ril_vendors=ril_vendors,
        telephony_allowed_baseband_patterns=baseband_patterns,
        package_expectations=package_expectations,
        camera_minimum_count=camera_minimum_count,
        camera_required_facing=camera_required_facing,
        camera_required_ids=camera_required_ids,
        camera_allowed_hardware_levels=camera_allowed_levels,
        camera_required_capabilities=camera_required_capabilities,
        sensors_minimum_count=sensors_minimum_count,
        sensors_required_types=sensors_required_types,
        sensors_allowed_vendors=sensors_allowed_vendors,
        hal_required_interfaces=hal_required_interfaces,
        hal_required_families=hal_required_families,
        hal_allowed_transports=hal_allowed_transports,
        audio_minimum_output_device_count=audio_minimum_output,
        audio_minimum_input_device_count=audio_minimum_input,
        audio_required_output_device_types=audio_output_types,
        audio_required_input_device_types=audio_input_types,
        audio_required_output_formats=audio_formats,
        audio_required_sample_rates=audio_rates,
        audio_require_service_available=audio_require_service,
        audio_require_policy_available=audio_require_policy,
        battery_require_present=battery_require_present,
        battery_allowed_health=battery_health,
        battery_allowed_plugged_sources=battery_plugged,
        battery_minimum_level_percent=battery_minimum_level,
        battery_maximum_temperature_tenths_c=battery_maximum_temperature,
        battery_require_property_service_available=battery_require_service,
        thermal_require_service_available=thermal_require_service,
        thermal_required_sensor_types=thermal_required_types,
        thermal_allowed_current_severity=thermal_severity,
        thermal_maximum_sensor_temperature_c=thermal_maximum,
        thermal_require_power_service_available=thermal_require_power,
        thermal_allowed_wakefulness=thermal_wakefulness,
        storage_required_filesystem_types=storage_filesystems,
        storage_required_mount_points=storage_mount_points,
        storage_require_data_mount_read_write=storage_require_rw,
        storage_minimum_data_available_kb=storage_minimum_available,
        storage_allowed_volume_types=storage_volume_types,
        storage_require_mount_service_available=storage_require_service,
        network_required_interfaces=network_interfaces,
        network_allowed_transport_types=network_transports,
        network_require_connectivity_service_available=network_require_service,
        graphics_allowed_gles_vendors=graphics_vendors,
        graphics_allowed_gles_renderer_patterns=graphics_renderer_patterns,
        graphics_require_surface_flinger_available=graphics_require_service,
        input_minimum_device_count=input_minimum_devices,
        input_required_device_classes=input_required_classes,
        memory_minimum_total_kb=memory_minimum_total,
        memory_maximum_total_kb=memory_maximum_total,
        memory_require_low_ram_flag=memory_require_low_ram,
    )


def _required_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ProfileValidationError(f"{key} must be a non-empty string")
    return value


def _string_mapping(value: Any, name: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ProfileValidationError(f"{name} must be an object")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ProfileValidationError(f"{name} contains an invalid key")
        if isinstance(item, bool) or not isinstance(item, (str, int)):
            raise ProfileValidationError(f"{name}.{key} must be a string or integer")
        result[key] = str(item)
    return result


def _string_list(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ProfileValidationError(f"{name} must be a list of non-empty strings")
    return tuple(dict.fromkeys(value))


def _integer_ranges(value: Any, name: str) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, list):
        raise ProfileValidationError(f"{name} must be a list")
    result: list[tuple[int, int]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ProfileValidationError(f"{name} entries must be objects")
        minimum = item.get("min")
        maximum = item.get("max")
        if (
            isinstance(minimum, bool)
            or isinstance(maximum, bool)
            or not isinstance(minimum, int)
            or not isinstance(maximum, int)
            or minimum < 0
            or maximum < minimum
        ):
            raise ProfileValidationError(f"{name} entries require integer min <= max")
        result.append((minimum, maximum))
    return tuple(result)

def _optional_nonnegative_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProfileValidationError(f"{name} must be a non-negative integer")
    return value


def _optional_bool(value: Any, name: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ProfileValidationError(f"{name} must be a boolean")
    return value


def _optional_bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int | None:
    parsed = _optional_nonnegative_int(value, name)
    if parsed is not None and not minimum <= parsed <= maximum:
        raise ProfileValidationError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _positive_integer_list(value: Any, name: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise ProfileValidationError(f"{name} must be a list")
    result: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise ProfileValidationError(f"{name} must contain positive integers")
        result.append(item)
    return tuple(dict.fromkeys(result))


def _float_mapping(value: Any, name: str) -> dict[str, float]:
    if not isinstance(value, dict):
        raise ProfileValidationError(f"{name} must be an object")
    result: dict[str, float] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ProfileValidationError(f"{name} keys must be non-empty strings")
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ProfileValidationError(f"{name} values must be numbers")
        result[key.upper()] = float(item)
    return dict(sorted(result.items()))


def _parse_package_expectations(value: Any) -> dict[str, PackageExpectation]:
    if not isinstance(value, dict):
        raise ProfileValidationError("packages must be an object")
    result: dict[str, PackageExpectation] = {}
    for package_name, expectation in value.items():
        if not isinstance(package_name, str) or not _PACKAGE_PATTERN.fullmatch(package_name):
            raise ProfileValidationError("packages contains an invalid package name")
        if not isinstance(expectation, dict):
            raise ProfileValidationError(f"packages.{package_name} must be an object")
        required = expectation.get("required", False)
        required_enabled = expectation.get("required_enabled")
        required_not_suspended = expectation.get("required_not_suspended")
        if not isinstance(required, bool):
            raise ProfileValidationError(f"packages.{package_name}.required must be a boolean")
        if required_enabled is not None and not isinstance(required_enabled, bool):
            raise ProfileValidationError(
                f"packages.{package_name}.required_enabled must be a boolean"
            )
        if required_not_suspended is not None and not isinstance(required_not_suspended, bool):
            raise ProfileValidationError(
                f"packages.{package_name}.required_not_suspended must be a boolean"
            )
        ranges = _integer_ranges(
            expectation.get("allowed_version_code_ranges", []),
            f"packages.{package_name}.allowed_version_code_ranges",
        )
        result[package_name] = PackageExpectation(
            required=required,
            allowed_version_code_ranges=ranges,
            required_enabled=required_enabled,
            required_not_suspended=required_not_suspended,
        )
    return result


def _parse_topology(value: Any) -> CpuTopology:
    if not isinstance(value, dict):
        raise ProfileValidationError("native_cpu.allowed_topologies entries must be objects")
    online_cpu_count = value.get("online_cpu_count")
    if isinstance(online_cpu_count, bool) or not isinstance(online_cpu_count, int) or online_cpu_count <= 0:
        raise ProfileValidationError("native_cpu topology online_cpu_count must be a positive integer")
    clusters_value = value.get("clusters")
    if not isinstance(clusters_value, list) or not clusters_value:
        raise ProfileValidationError("native_cpu topology clusters must be a non-empty list")
    clusters: list[CpuCluster] = []
    for cluster in clusters_value:
        if not isinstance(cluster, dict):
            raise ProfileValidationError("native_cpu cluster must be an object")
        implementer = cluster.get("implementer")
        part = cluster.get("part")
        count = cluster.get("count")
        if not isinstance(implementer, str) or not implementer:
            raise ProfileValidationError("native_cpu cluster implementer must be a non-empty string")
        if not isinstance(part, str) or not part:
            raise ProfileValidationError("native_cpu cluster part must be a non-empty string")
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ProfileValidationError("native_cpu cluster count must be a positive integer")
        clusters.append(CpuCluster(implementer=implementer.lower(), part=part.lower(), count=count))
    return CpuTopology(
        online_cpu_count=online_cpu_count,
        clusters=tuple(sorted(clusters, key=lambda cluster: (cluster.implementer, cluster.part))),
    )
