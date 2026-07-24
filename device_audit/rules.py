"""Profile-driven rules for observable read-only device inventory."""

from __future__ import annotations

import json
from collections.abc import Mapping
import re

from device_audit.models import (
    AudioInventory,
    BatteryInventory,
    CameraInventory,
    Comparison,
    CpuTopology,
    DisplayInfo,
    ExpectedProfile,
    Finding,
    HalInventory,
    KernelInfo,
    PackageInfo,
    SensorInventory,
    StorageInventory,
    TelephonyInfo,
    ThermalInventory,
)

_IDENTITY_PROPERTIES = {
    "brand": "ro.product.brand",
    "manufacturer": "ro.product.manufacturer",
    "model": "ro.product.model",
    "device": "ro.product.device",
    "product": "ro.product.name",
}
_BUILD_PROPERTIES = {
    "id": "ro.build.id",
    "incremental": "ro.build.version.incremental",
    "release": "ro.build.version.release",
    "sdk": "ro.build.version.sdk",
    "security_patch": "ro.build.version.security_patch",
    "fingerprint": "ro.build.fingerprint",
    "description": "ro.build.description",
}


def evaluate_profile(
    properties: dict[str, str],
    kernel: KernelInfo | None,
    cpu: CpuTopology | None,
    profile: ExpectedProfile | None,
    display: DisplayInfo | None = None,
    telephony: TelephonyInfo | None = None,
    packages: Mapping[str, PackageInfo] | None = None,
    camera: CameraInventory | None = None,
    sensors: SensorInventory | None = None,
    hal: HalInventory | None = None,
    audio: AudioInventory | None = None,
    battery: BatteryInventory | None = None,
    thermal: ThermalInventory | None = None,
    storage: StorageInventory | None = None,
) -> list[Finding]:
    """Evaluate only those expectations explicitly declared by a profile."""

    comparisons = compare_profile(
        properties,
        kernel,
        cpu,
        profile,
        display,
        telephony,
        packages,
        camera,
        sensors,
        hal,
        audio,
        battery,
        thermal,
        storage,
    )
    findings: list[Finding] = []
    for comparison in comparisons:
        if comparison.status != "mismatched":
            continue
        if comparison.field == "kernel.lineage":
            findings.append(_kernel_finding(comparison))
        elif comparison.field == "native_cpu.topology":
            findings.append(_cpu_finding(comparison))
        elif comparison.category == "display":
            findings.append(_display_finding(comparison))
        elif comparison.category == "telephony":
            findings.append(_telephony_finding(comparison))
        elif comparison.category == "packages":
            findings.append(_package_finding(comparison))
        elif comparison.category == "camera":
            findings.append(_camera_finding(comparison))
        elif comparison.category == "sensors":
            findings.append(_sensors_finding(comparison))
        elif comparison.category == "hal":
            findings.append(_hal_finding(comparison))
        elif comparison.category == "audio":
            findings.append(_phase4_finding(comparison, "AUDIO_PROFILE_MISMATCH", "Audio inventory differs from the selected profile's explicit reference."))
        elif comparison.category == "battery":
            findings.append(_phase4_finding(comparison, "BATTERY_PROFILE_MISMATCH", "Battery inventory differs from the selected profile's explicit reference."))
        elif comparison.category == "thermal":
            findings.append(_phase4_finding(comparison, "THERMAL_PROFILE_MISMATCH", "Thermal or power inventory differs from the selected profile's explicit reference."))
        elif comparison.category == "storage":
            findings.append(_phase4_finding(comparison, "STORAGE_PROFILE_MISMATCH", "Storage inventory differs from the selected profile's explicit reference."))
        else:
            findings.append(_property_finding(comparison))
    return findings


def compare_profile(
    properties: dict[str, str],
    kernel: KernelInfo | None,
    cpu: CpuTopology | None,
    profile: ExpectedProfile | None,
    display: DisplayInfo | None = None,
    telephony: TelephonyInfo | None = None,
    packages: Mapping[str, PackageInfo] | None = None,
    camera: CameraInventory | None = None,
    sensors: SensorInventory | None = None,
    hal: HalInventory | None = None,
    audio: AudioInventory | None = None,
    battery: BatteryInventory | None = None,
    thermal: ThermalInventory | None = None,
    storage: StorageInventory | None = None,
) -> list[Comparison]:
    """Return explicit matched, mismatched, or not-evaluated comparison states."""

    if profile is None:
        return []
    comparisons = _compare_property_fields(properties, profile.identity, _IDENTITY_PROPERTIES, "identity")
    comparisons.extend(_compare_property_fields(properties, profile.build, _BUILD_PROPERTIES, "build"))
    comparisons.append(_compare_kernel(kernel, profile))
    comparisons.append(_compare_cpu(cpu, profile))
    comparisons.extend(_compare_display(display, profile))
    comparisons.extend(_compare_telephony(telephony, profile))
    comparisons.extend(_compare_packages(packages or {}, profile))
    comparisons.extend(_compare_camera(camera, profile))
    comparisons.extend(_compare_sensors(sensors, profile))
    comparisons.extend(_compare_hal(hal, profile))
    comparisons.extend(_compare_audio(audio, profile))
    comparisons.extend(_compare_battery(battery, profile))
    comparisons.extend(_compare_thermal(thermal, profile))
    comparisons.extend(_compare_storage(storage, profile))
    return comparisons


def _compare_property_fields(
    properties: dict[str, str],
    expected_fields: Mapping[str, str],
    property_names: dict[str, str],
    category: str,
) -> list[Comparison]:
    comparisons: list[Comparison] = []
    for field, expected in expected_fields.items():
        property_name = property_names.get(field)
        observed = properties.get(property_name) if property_name else None
        status = "not_evaluated" if observed is None else "matched" if observed == expected else "mismatched"
        comparisons.append(
            Comparison(
                field=f"{category}.{field}",
                category=category,
                status=status,
                expected=expected,
                observed=observed,
                evidence=(property_name or field,),
            )
        )
    return comparisons


def _compare_kernel(kernel: KernelInfo | None, profile: ExpectedProfile) -> Comparison:
    expected = ", ".join(profile.kernel_allowed_lineages) if profile.kernel_allowed_lineages else None
    observed = kernel.lineage if kernel else None
    if not profile.kernel_allowed_lineages or observed is None:
        status = "not_evaluated"
    else:
        status = "matched" if observed in profile.kernel_allowed_lineages else "mismatched"
    return Comparison(
        field="kernel.lineage",
        category="kernel",
        status=status,
        expected=expected,
        observed=observed,
        evidence=("kernel.osrelease",),
    )


def _compare_cpu(cpu: CpuTopology | None, profile: ExpectedProfile) -> Comparison:
    expected = [
        {
            "online_cpu_count": topology.online_cpu_count,
            "clusters": [cluster.__dict__ for cluster in topology.clusters],
        }
        for topology in profile.allowed_cpu_topologies
    ]
    observed_mapping = None
    if cpu is not None:
        observed_mapping = {
            "online_cpu_count": cpu.online_cpu_count,
            "clusters": [cluster.__dict__ for cluster in cpu.clusters],
        }
    if not profile.allowed_cpu_topologies or cpu is None or cpu.online_cpu_count is None:
        status = "not_evaluated"
    else:
        status = "matched" if any(cpu == allowed for allowed in profile.allowed_cpu_topologies) else "mismatched"
    return Comparison(
        field="native_cpu.topology",
        category="cpu",
        status=status,
        expected=json.dumps(expected, sort_keys=True) if expected else None,
        observed=json.dumps(observed_mapping, sort_keys=True) if observed_mapping else None,
        evidence=("cpuinfo", "online_cpu_count"),
    )


def _compare_display(display: DisplayInfo | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    if profile.display_allowed_physical_sizes:
        observed = display.physical_size if display else None
        comparisons.append(
            _allowed_comparison(
                "display.physical_size",
                "display",
                list(profile.display_allowed_physical_sizes),
                observed,
                ("display.wm_size",),
            )
        )
    if profile.display_allowed_density_ranges:
        observed_density = display.physical_density if display else None
        expected = json.dumps(
            [{"min": minimum, "max": maximum} for minimum, maximum in profile.display_allowed_density_ranges],
            sort_keys=True,
        )
        observed = str(observed_density) if observed_density is not None else None
        status = "not_evaluated" if observed_density is None else "matched" if any(
            minimum <= observed_density <= maximum
            for minimum, maximum in profile.display_allowed_density_ranges
        ) else "mismatched"
        comparisons.append(
            Comparison("display.physical_density", "display", status, expected, observed, ("display.wm_density",))
        )
    if profile.display_allowed_refresh_rates:
        observed_rates = list(display.refresh_rates) if display else None
        expected = json.dumps(list(profile.display_allowed_refresh_rates), sort_keys=True)
        observed = json.dumps(observed_rates, sort_keys=True) if observed_rates else None
        status = "not_evaluated" if not observed_rates else "matched" if set(observed_rates).issubset(
            set(profile.display_allowed_refresh_rates)
        ) else "mismatched"
        comparisons.append(
            Comparison("display.refresh_rates", "display", status, expected, observed, ("display.dumpsys",))
        )
    return comparisons


def _compare_telephony(telephony: TelephonyInfo | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    observed_values: dict[str, tuple[str, ...] | None] = {
        "operator_numeric": telephony.operator_numeric if telephony else None,
        "country_iso": telephony.operator_country_iso if telephony else None,
        "network_types": telephony.network_types if telephony else None,
        "ril_vendors": (telephony.ril_implementation,) if telephony and telephony.ril_implementation else None,
    }
    expectations = {
        "operator_numeric": profile.telephony_allowed_operator_numeric,
        "country_iso": profile.telephony_allowed_country_iso,
        "network_types": profile.telephony_allowed_network_types,
        "ril_vendors": profile.telephony_allowed_ril_vendors,
    }
    evidence = {
        "operator_numeric": ("properties.getprop", "telephony.registry"),
        "country_iso": ("properties.getprop", "telephony.registry"),
        "network_types": ("properties.getprop", "telephony.registry"),
        "ril_vendors": ("properties.getprop",),
    }
    for name, allowed in expectations.items():
        if allowed:
            observed_value = observed_values[name]
            comparisons.append(
                _allowed_comparison(
                    f"telephony.{name}",
                    "telephony",
                    list(allowed),
                    list(observed_value) if observed_value is not None else None,
                    evidence[name],
                )
            )
    if profile.telephony_allowed_baseband_patterns:
        observed = telephony.baseband if telephony else None
        expected = json.dumps(list(profile.telephony_allowed_baseband_patterns), sort_keys=True)
        status = "not_evaluated" if not observed else "matched" if any(
            re.search(pattern, observed) for pattern in profile.telephony_allowed_baseband_patterns
        ) else "mismatched"
        comparisons.append(
            Comparison("telephony.baseband", "telephony", status, expected, observed, ("properties.getprop",))
        )
    return comparisons


def _compare_packages(
    packages: Mapping[str, PackageInfo],
    profile: ExpectedProfile,
) -> list[Comparison]:
    comparisons: list[Comparison] = []
    for package_name, expectation in profile.package_expectations.items():
        package = packages.get(package_name)
        if expectation.required:
            observed = None if package is None or package.installed is None else str(package.installed).lower()
            comparisons.append(
                Comparison(
                    f"packages.{package_name}.installed",
                    "packages",
                    "not_evaluated" if observed is None else "matched" if observed == "true" else "mismatched",
                    "true",
                    observed,
                    (f"packages.{package_name}.path",),
                )
            )
        if expectation.allowed_version_code_ranges:
            observed_code = package.version_code if package and package.installed else None
            expected = json.dumps(
                [{"min": minimum, "max": maximum} for minimum, maximum in expectation.allowed_version_code_ranges],
                sort_keys=True,
            )
            status = "not_evaluated" if observed_code is None else "matched" if any(
                minimum <= observed_code <= maximum
                for minimum, maximum in expectation.allowed_version_code_ranges
            ) else "mismatched"
            comparisons.append(
                Comparison(
                    f"packages.{package_name}.version_code",
                    "packages",
                    status,
                    expected,
                    str(observed_code) if observed_code is not None else None,
                    (f"packages.{package_name}.dumpsys",),
                )
            )
        if expectation.required_enabled is not None:
            observed_enabled = package.enabled if package else None
            comparisons.append(
                Comparison(
                    f"packages.{package_name}.enabled",
                    "packages",
                    "not_evaluated" if observed_enabled is None else "matched" if observed_enabled == expectation.required_enabled else "mismatched",
                    str(expectation.required_enabled).lower(),
                    str(observed_enabled).lower() if observed_enabled is not None else None,
                    (f"packages.{package_name}.dumpsys",),
                )
            )
        if expectation.required_not_suspended:
            observed_suspended = package.suspended if package else None
            comparisons.append(
                Comparison(
                    f"packages.{package_name}.not_suspended",
                    "packages",
                    "not_evaluated" if observed_suspended is None else "matched" if observed_suspended is False else "mismatched",
                    "true",
                    str(not observed_suspended).lower() if observed_suspended is not None else None,
                    (f"packages.{package_name}.dumpsys",),
                )
            )
    return comparisons

def _compare_camera(camera: CameraInventory | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    if profile.camera_minimum_count is not None:
        observed_count = camera.camera_count if camera else None
        comparisons.append(
            Comparison(
                "camera.minimum_camera_count",
                "camera",
                "not_evaluated" if observed_count is None else "matched" if observed_count >= profile.camera_minimum_count else "mismatched",
                str(profile.camera_minimum_count),
                str(observed_count) if observed_count is not None else None,
                ("camera.media_camera", "camera.cmd_list"),
            )
        )
    if profile.camera_required_facing:
        observed_facing = {item.facing for item in camera.cameras} if camera else None
        comparisons.append(
            _required_values_comparison(
                "camera.required_facing",
                "camera",
                profile.camera_required_facing,
                observed_facing,
                ("camera.media_camera",),
            )
        )
    if profile.camera_required_ids:
        observed_ids = {item.id for item in camera.cameras} if camera else None
        comparisons.append(
            _required_values_comparison(
                "camera.required_camera_ids",
                "camera",
                profile.camera_required_ids,
                observed_ids,
                ("camera.media_camera", "camera.cmd_list"),
            )
        )
    if profile.camera_allowed_hardware_levels:
        candidates = list(camera.cameras) if camera else None
        if candidates is not None and profile.camera_required_ids:
            required_ids = set(profile.camera_required_ids)
            candidates = [item for item in candidates if item.id in required_ids]
        elif candidates is not None and profile.camera_required_facing:
            required_facing = set(profile.camera_required_facing)
            candidates = [item for item in candidates if item.facing in required_facing]
        observed_hardware_levels = [item.hardware_level for item in candidates if item.hardware_level != "UNKNOWN"] if candidates is not None else None
        comparisons.append(
            _allowed_comparison(
                "camera.hardware_levels",
                "camera",
                list(profile.camera_allowed_hardware_levels),
                observed_hardware_levels,
                ("camera.media_camera",),
            )
        )
    if profile.camera_required_capabilities:
        observed_capabilities = {capability for item in camera.cameras for capability in item.capability_names} if camera else None
        comparisons.append(
            _required_values_comparison(
                "camera.required_capabilities",
                "camera",
                profile.camera_required_capabilities,
                observed_capabilities,
                ("camera.media_camera", "camera.cmd_dump"),
            )
        )
    return comparisons

def _compare_sensors(sensors: SensorInventory | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    if profile.sensors_minimum_count is not None:
        observed_count = sensors.sensor_count if sensors else None
        comparisons.append(
            Comparison(
                "sensors.minimum_sensor_count",
                "sensors",
                "not_evaluated" if observed_count is None else "matched" if observed_count >= profile.sensors_minimum_count else "mismatched",
                str(profile.sensors_minimum_count),
                str(observed_count) if observed_count is not None else None,
                ("sensors.sensorservice",),
            )
        )
    if profile.sensors_required_types:
        observed_types = set(sensors.type_counts) if sensors else None
        comparisons.append(
            _required_values_comparison(
                "sensors.required_types",
                "sensors",
                profile.sensors_required_types,
                observed_types,
                ("sensors.sensorservice",),
            )
        )
    if profile.sensors_allowed_vendors:
        observed_vendors = list(sensors.vendor_counts) if sensors else None
        comparisons.append(
            _allowed_comparison(
                "sensors.vendors",
                "sensors",
                list(profile.sensors_allowed_vendors),
                observed_vendors,
                ("sensors.sensorservice",),
            )
        )
    return comparisons

def _compare_hal(hal: HalInventory | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    if profile.hal_required_interfaces:
        observed_interfaces = [item.full_interface for item in hal.interfaces] if hal else None
        status = "not_evaluated"
        if observed_interfaces is not None:
            status = "matched" if all(
                any(_hal_interface_matches(expected, actual) for actual in observed_interfaces)
                for expected in profile.hal_required_interfaces
            ) else "mismatched"
        comparisons.append(
            Comparison(
                "hal.required_interfaces",
                "hal",
                status,
                json.dumps(list(profile.hal_required_interfaces), sort_keys=True),
                json.dumps(observed_interfaces, sort_keys=True) if observed_interfaces is not None else None,
                ("hal.lshal", "hal.lshal_interfaces", "hal.dumpsys_services"),
            )
        )
    if profile.hal_required_families:
        observed_families = set(hal.families) if hal else None
        comparisons.append(
            _required_values_comparison(
                "hal.required_families",
                "hal",
                profile.hal_required_families,
                observed_families,
                ("hal.lshal", "hal.lshal_interfaces", "hal.dumpsys_services"),
            )
        )
    if profile.hal_allowed_transports:
        observed_transports = [item.transport for item in hal.interfaces if item.transport != "unknown"] if hal else None
        comparisons.append(
            _allowed_comparison(
                "hal.transports",
                "hal",
                list(profile.hal_allowed_transports),
                observed_transports,
                ("hal.lshal", "hal.lshal_interfaces", "hal.dumpsys_services"),
            )
        )
    return comparisons


def _compare_audio(audio: AudioInventory | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    usable_audio = audio if audio and audio.service_status != "unavailable" and (audio.output_devices or audio.input_devices or not audio.parse_warnings) else None
    if profile.audio_minimum_output_device_count is not None:
        comparisons.append(_minimum_comparison(
            "audio.output_device_count", "audio", profile.audio_minimum_output_device_count,
            len(usable_audio.output_devices) if usable_audio else None, ("audio.dumpsys_audio",),
        ))
    if profile.audio_minimum_input_device_count is not None:
        comparisons.append(_minimum_comparison(
            "audio.input_device_count", "audio", profile.audio_minimum_input_device_count,
            len(usable_audio.input_devices) if usable_audio else None, ("audio.dumpsys_audio",),
        ))
    if profile.audio_required_output_device_types:
        comparisons.append(_required_values_comparison(
            "audio.required_output_device_types", "audio", profile.audio_required_output_device_types,
            {device.device_type for device in usable_audio.output_devices if device.device_type} if usable_audio else None,
            ("audio.dumpsys_audio", "audio.policy_ports"),
        ))
    if profile.audio_required_input_device_types:
        comparisons.append(_required_values_comparison(
            "audio.required_input_device_types", "audio", profile.audio_required_input_device_types,
            {device.device_type for device in usable_audio.input_devices if device.device_type} if usable_audio else None,
            ("audio.dumpsys_audio", "audio.policy_ports"),
        ))
    if profile.audio_required_output_formats:
        comparisons.append(_required_values_comparison(
            "audio.required_output_formats", "audio", profile.audio_required_output_formats,
            {value for device in usable_audio.output_devices for value in device.formats} if usable_audio else None,
            ("audio.dumpsys_audio", "audio.policy_ports"),
        ))
    if profile.audio_required_sample_rates:
        observed = {str(rate) for device in usable_audio.output_devices for rate in device.sample_rates} if usable_audio else None
        comparisons.append(_required_values_comparison(
            "audio.required_sample_rates", "audio", tuple(str(rate) for rate in profile.audio_required_sample_rates),
            observed, ("audio.dumpsys_audio", "audio.policy_ports"),
        ))
    if profile.audio_require_service_available is not None:
        comparisons.append(_status_bool_comparison(
            "audio.service_available", "audio", profile.audio_require_service_available,
            audio.service_status == "available" if audio and audio.service_status is not None else None,
            ("audio.dumpsys_audio",),
        ))
    if profile.audio_require_policy_available is not None:
        comparisons.append(_status_bool_comparison(
            "audio.policy_available", "audio", profile.audio_require_policy_available,
            audio.audio_policy_status == "available" if audio and audio.audio_policy_status is not None else None,
            ("audio.audio_policy", "audio.policy_ports"),
        ))
    return comparisons


def _compare_battery(battery: BatteryInventory | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    if profile.battery_require_present is not None:
        comparisons.append(_status_bool_comparison(
            "battery.present", "battery", profile.battery_require_present,
            battery.battery_present if battery else None, ("battery.dumpsys_battery",),
        ))
    if profile.battery_allowed_health:
        comparisons.append(_allowed_comparison(
            "battery.health", "battery", list(profile.battery_allowed_health),
            battery.battery_health if battery else None, ("battery.dumpsys_battery", "battery.cmd_health"),
        ))
    if profile.battery_allowed_plugged_sources:
        comparisons.append(_allowed_comparison(
            "battery.plugged_source", "battery", list(profile.battery_allowed_plugged_sources),
            battery.plugged_source if battery else None, ("battery.dumpsys_battery", "battery.cmd_plugged"),
        ))
    if profile.battery_minimum_level_percent is not None:
        comparisons.append(_minimum_comparison(
            "battery.level_percent", "battery", profile.battery_minimum_level_percent,
            battery.level_percent if battery else None, ("battery.dumpsys_battery", "battery.cmd_level"),
        ))
    if profile.battery_maximum_temperature_tenths_c is not None:
        observed = battery.temperature_tenths_c if battery else None
        comparisons.append(_maximum_comparison(
            "battery.temperature_tenths_c", "battery", profile.battery_maximum_temperature_tenths_c,
            observed, ("battery.dumpsys_battery", "battery.cmd_temperature"),
        ))
    if profile.battery_require_property_service_available is not None:
        comparisons.append(_status_bool_comparison(
            "battery.property_service_available", "battery", profile.battery_require_property_service_available,
            battery.property_service_status == "available" if battery and battery.property_service_status is not None else None,
            ("battery.properties",),
        ))
    return comparisons


def _compare_thermal(thermal: ThermalInventory | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    if profile.thermal_require_service_available is not None:
        comparisons.append(_status_bool_comparison(
            "thermal.service_available", "thermal", profile.thermal_require_service_available,
            thermal.thermal_service_status == "available" if thermal and thermal.thermal_service_status is not None else None,
            ("thermal.service", "thermal.cmd_dump"),
        ))
    if profile.thermal_required_sensor_types:
        comparisons.append(_required_values_comparison(
            "thermal.required_sensor_types", "thermal", profile.thermal_required_sensor_types,
            {sensor.type for sensor in thermal.temperature_sensors} if thermal else None,
            ("thermal.service", "thermal.cmd_dump"),
        ))
    if profile.thermal_allowed_current_severity:
        comparisons.append(_allowed_comparison(
            "thermal.current_severity", "thermal", list(profile.thermal_allowed_current_severity),
            thermal.current_thermal_severity if thermal else None, ("thermal.service", "thermal.cmd_dump"),
        ))
    for sensor_type, maximum in profile.thermal_maximum_sensor_temperature_c.items():
        observed_values = [sensor.temperature_c for sensor in thermal.temperature_sensors if sensor.type == sensor_type and sensor.temperature_c is not None] if thermal else None
        comparisons.append(_maximum_comparison(
            f"thermal.maximum_temperature.{sensor_type}", "thermal", maximum,
            max(observed_values) if observed_values else None, ("thermal.service", "thermal.cmd_dump"),
        ))
    if profile.thermal_require_power_service_available is not None:
        comparisons.append(_status_bool_comparison(
            "thermal.power_service_available", "thermal", profile.thermal_require_power_service_available,
            thermal.power_service_status == "available" if thermal and thermal.power_service_status is not None else None,
            ("thermal.power",),
        ))
    if profile.thermal_allowed_wakefulness:
        comparisons.append(_allowed_comparison(
            "thermal.wakefulness", "thermal", list(profile.thermal_allowed_wakefulness),
            thermal.wakefulness if thermal else None, ("thermal.power", "thermal.deviceidle"),
        ))
    return comparisons


def _compare_storage(storage: StorageInventory | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    if profile.storage_required_filesystem_types:
        comparisons.append(_required_values_comparison(
            "storage.required_filesystem_types", "storage", profile.storage_required_filesystem_types,
            {mount.filesystem for mount in storage.mounts if mount.filesystem} if storage else None,
            ("storage.mount", "storage.proc_mounts"),
        ))
    if profile.storage_required_mount_points:
        comparisons.append(_required_values_comparison(
            "storage.required_mount_points", "storage", profile.storage_required_mount_points,
            {mount.target for mount in storage.mounts} if storage else None,
            ("storage.mount", "storage.proc_mounts", "storage.df_k"),
        ))
    if profile.storage_require_data_mount_read_write is not None:
        data_mount = next((mount for mount in storage.mounts if mount.target == "/data"), None) if storage else None
        comparisons.append(_status_bool_comparison(
            "storage.data_mount_read_write", "storage", profile.storage_require_data_mount_read_write,
            data_mount.read_only is False if data_mount and data_mount.read_only is not None else None,
            ("storage.mount", "storage.proc_mounts"),
        ))
    if profile.storage_minimum_data_available_kb is not None:
        data_mount = next((mount for mount in storage.mounts if mount.target == "/data"), None) if storage else None
        comparisons.append(_minimum_comparison(
            "storage.data_available_kb", "storage", profile.storage_minimum_data_available_kb,
            data_mount.available_kb if data_mount else None, ("storage.df_k",),
        ))
    if profile.storage_allowed_volume_types:
        comparisons.append(_allowed_comparison(
            "storage.volume_types", "storage", list(profile.storage_allowed_volume_types),
            [volume.type for volume in storage.volumes] if storage and storage.volumes else None,
            ("storage.volumes",),
        ))
    if profile.storage_require_mount_service_available is not None:
        comparisons.append(_status_bool_comparison(
            "storage.mount_service_available", "storage", profile.storage_require_mount_service_available,
            storage.mount_service_status == "available" if storage and storage.mount_service_status is not None else None,
            ("storage.dumpsys_mount",),
        ))
    return comparisons


def _minimum_comparison(field: str, category: str, expected: int | float, observed: int | float | None, evidence: tuple[str, ...]) -> Comparison:
    return Comparison(field, category, "not_evaluated" if observed is None else "matched" if observed >= expected else "mismatched", str(expected), str(observed) if observed is not None else None, evidence)


def _maximum_comparison(field: str, category: str, expected: int | float, observed: int | float | None, evidence: tuple[str, ...]) -> Comparison:
    return Comparison(field, category, "not_evaluated" if observed is None else "matched" if observed <= expected else "mismatched", str(expected), str(observed) if observed is not None else None, evidence)


def _status_bool_comparison(field: str, category: str, expected: bool, observed: bool | None, evidence: tuple[str, ...]) -> Comparison:
    return Comparison(field, category, "not_evaluated" if observed is None else "matched" if observed == expected else "mismatched", str(expected).lower(), str(observed).lower() if observed is not None else None, evidence)

def _required_values_comparison(
    field: str,
    category: str,
    required: tuple[str, ...],
    observed: set[str] | None,
    evidence: tuple[str, ...],
) -> Comparison:
    expected = json.dumps(list(required), sort_keys=True)
    if observed is None:
        return Comparison(field, category, "not_evaluated", expected, None, evidence)
    return Comparison(
        field,
        category,
        "matched" if set(required) <= observed else "mismatched",
        expected,
        json.dumps(sorted(observed), sort_keys=True),
        evidence,
    )

def _hal_interface_matches(expected: str, observed: str) -> bool:
    return observed == expected or observed.startswith(f"{expected}@") or observed.startswith(f"{expected}.")


def _allowed_comparison(
    field: str,
    category: str,
    allowed: list[str],
    observed: str | tuple[str, ...] | list[str] | None,
    evidence: tuple[str, ...],
) -> Comparison:
    expected = json.dumps(allowed, sort_keys=True)
    if observed is None or observed == []:
        status = "not_evaluated"
        observed_text = None
    else:
        values = [observed] if isinstance(observed, str) else list(observed)
        status = "matched" if all(value in allowed for value in values) else "mismatched"
        observed_text = json.dumps(values, sort_keys=True)
    return Comparison(field, category, status, expected, observed_text, evidence)


def _property_finding(comparison: Comparison) -> Finding:
    return Finding(
        id="PROFILE_FIELD_MISMATCH",
        title="Expected profile field differs",
        category=comparison.category,
        severity="medium",
        confidence="high",
        summary=f"Expected {comparison.field} to be {comparison.expected!r}, observed {comparison.observed!r}.",
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Review the selected profile and the observed property layer.",
    )


def _kernel_finding(comparison: Comparison) -> Finding:
    return Finding(
        id="KERNEL_LINEAGE_MISMATCH",
        title="Kernel lineage differs from profile reference",
        category="kernel",
        severity="medium",
        confidence="high",
        summary="The observable kernel lineage is not one of the profile's allowed lineages.",
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Confirm the profile's trusted kernel reference data before drawing conclusions.",
    )


def _cpu_finding(comparison: Comparison) -> Finding:
    return Finding(
        id="CPU_TOPOLOGY_MISMATCH",
        title="Native CPU topology differs from profile reference",
        category="cpu",
        severity="medium",
        confidence="high",
        summary="The observable CPU topology does not match any profile-declared topology.",
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Confirm the profile's trusted native CPU reference data before drawing conclusions.",
    )


def _display_finding(comparison: Comparison) -> Finding:
    return _phase2_finding(
        comparison,
        "DISPLAY_PROFILE_MISMATCH",
        "Display observation differs from the selected profile's explicit reference.",
    )


def _telephony_finding(comparison: Comparison) -> Finding:
    return _phase2_finding(
        comparison,
        "TELEPHONY_PROFILE_MISMATCH",
        "Telephony observation differs from the selected profile's explicit reference.",
    )


def _package_finding(comparison: Comparison) -> Finding:
    return _phase2_finding(
        comparison,
        "PACKAGE_PROFILE_MISMATCH",
        "Package metadata differs from the selected profile's explicit reference.",
    )

def _camera_finding(comparison: Comparison) -> Finding:
    return _phase3_finding(
        comparison,
        "CAMERA_PROFILE_MISMATCH",
        "Camera inventory differs from the selected profile's explicit reference.",
    )

def _sensors_finding(comparison: Comparison) -> Finding:
    return _phase3_finding(
        comparison,
        "SENSORS_PROFILE_MISMATCH",
        "Sensor inventory differs from the selected profile's explicit reference.",
    )

def _hal_finding(comparison: Comparison) -> Finding:
    return _phase3_finding(
        comparison,
        "HAL_PROFILE_MISMATCH",
        "HAL inventory differs from the selected profile's explicit reference.",
    )


def _phase2_finding(comparison: Comparison, finding_id: str, summary: str) -> Finding:
    return Finding(
        id=finding_id,
        title="Explicit profile expectation differs",
        category=comparison.category,
        severity="medium",
        confidence="high",
        summary=summary,
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Review the selected profile and the observed evidence before drawing conclusions.",
    )

def _phase3_finding(comparison: Comparison, finding_id: str, summary: str) -> Finding:
    return Finding(
        id=finding_id,
        title="Explicit hardware inventory expectation differs",
        category=comparison.category,
        severity="medium",
        confidence="high",
        summary=summary,
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Review the selected profile and observed hardware inventory before drawing conclusions.",
    )


def _phase4_finding(comparison: Comparison, finding_id: str, summary: str) -> Finding:
    return Finding(
        id=finding_id,
        title="Explicit system inventory expectation differs",
        category=comparison.category,
        severity="medium",
        confidence="high",
        summary=summary,
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Review the selected profile and observed system inventory before drawing conclusions.",
    )
