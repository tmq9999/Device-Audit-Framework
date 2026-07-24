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
    if not schema_version.startswith(("1.", "2.", "3.")):
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
