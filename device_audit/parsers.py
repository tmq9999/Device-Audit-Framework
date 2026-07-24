"""Defensive parsers for Phase 1 Android device evidence."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
import re

from device_audit.models import (
    AudioDevice,
    AudioInventory,
    BatteryInventory,
    CameraDevice,
    CameraInventory,
    CoolingDevice,
    CpuCluster,
    CpuTopology,
    DisplayInfo,
    DisplayMode,
    FilesystemSupport,
    GraphicsInventory,
    HalInterface,
    HalInventory,
    InputDevice,
    InputInventory,
    KernelInfo,
    MagiskInfo,
    MemoryInventory,
    NetworkInterface,
    NetworkInventory,
    PackageInfo,
    RuntimeMarkers,
    SensorDevice,
    SensorInventory,
    StorageInventory,
    StorageMount,
    StoragePartition,
    StorageVolume,
    TelephonyInfo,
    ThermalInventory,
    ThermalSensor,
)

_GETPROP_PATTERN = re.compile(r"^\[([^]]+)\]: \[(.*)]$")
_KERNEL_RELEASE_PATTERN = re.compile(r"^Linux\s+\S+\s+(\S+)")
_KERNEL_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)")
_KERNEL_RELEASE_TOKEN_PATTERN = re.compile(r"\b(\d+\.\d+(?:\.\d+)?[^\s]*)")
_ANDROID_BRANCH_PATTERN = re.compile(r"\bandroid(\d+)\b")
_ARCHITECTURE_PATTERN = re.compile(r"\b(aarch64|armv[0-9]+l|x86_64|i[3-6]86)\b", re.IGNORECASE)


def parse_getprop(text: str) -> dict[str, str]:
    """Parse `getprop` output into a property mapping."""

    properties: dict[str, str] = {}
    for line in text.splitlines():
        match = _GETPROP_PATTERN.match(line.strip())
        if match:
            properties[match.group(1)] = match.group(2)
    return properties


def parse_kernel_info(text: str) -> KernelInfo:
    """Parse a kernel release string without inferring unsupported lineage."""

    release_match = _KERNEL_RELEASE_PATTERN.search(text.strip())
    release = release_match.group(1) if release_match else None
    if release and not _KERNEL_VERSION_PATTERN.match(release):
        release = None
    if release is None:
        token_match = _KERNEL_RELEASE_TOKEN_PATTERN.search(text)
        release = token_match.group(1) if token_match else None
    version_match = _KERNEL_VERSION_PATTERN.search(release or "")
    branch_match = _ANDROID_BRANCH_PATTERN.search(release or "")
    lineage = None
    if version_match and branch_match:
        lineage = f"android{branch_match.group(1)}-{version_match.group(1)}.{version_match.group(2)}"
    architecture_match = _ARCHITECTURE_PATTERN.search(text)
    architecture = architecture_match.group(1).lower() if architecture_match else None
    return KernelInfo(release=release, lineage=lineage, architecture=architecture)


def parse_cpuinfo(text: str, online_cpu_count: int | None = None) -> CpuTopology:
    """Parse ARM implementer/part records into a normalized CPU topology."""

    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if ":" not in stripped:
            continue
        key, value = (part.strip() for part in stripped.split(":", 1))
        if key == "processor":
            if current:
                records.append(current)
                current = {}
            continue
        if key in {"CPU implementer", "CPU part"}:
            current[key] = value.lower()
    if current:
        records.append(current)

    counts: Counter[tuple[str, str]] = Counter()
    for record in records:
        implementer = record.get("CPU implementer")
        part = record.get("CPU part")
        if implementer and part:
            counts[(implementer, part)] += 1
    clusters = tuple(
        CpuCluster(implementer=implementer, part=part, count=count)
        for (implementer, part), count in sorted(counts.items())
    )
    detected_count = online_cpu_count if online_cpu_count is not None else len(records)
    return CpuTopology(online_cpu_count=detected_count or None, clusters=clusters)


def parse_online_cpu_count(text: str) -> int | None:
    """Parse the first positive integer from an online CPU count command."""

    value = text.strip()
    if not value:
        return None
    if re.fullmatch(r"\d+", value):
        integer = int(value)
        return integer if integer > 0 else None
    if re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        count = 0
        for segment in value.split(","):
            if "-" not in segment:
                count += 1
                continue
            start_text, end_text = segment.split("-", 1)
            start, end = int(start_text), int(end_text)
            if end < start:
                return None
            count += end - start + 1
        return count
    return None


def parse_display_info(
    wm_size_text: str,
    wm_density_text: str,
    display_text: str,
    window_displays_text: str,
) -> DisplayInfo:
    """Parse display geometry and capabilities across Android formatting variants."""

    physical_size = _parse_display_size(wm_size_text, "physical")
    override_size = _parse_display_size(wm_size_text, "override")
    physical_density = _parse_display_density(wm_density_text, "physical")
    override_density = _parse_display_density(wm_density_text, "override")
    combined = f"{display_text}\n{window_displays_text}"
    logical_width, logical_height = _parse_logical_size(combined)
    modes = _parse_display_modes(display_text)
    refresh_rates = _unique_floats(
        [mode.refresh_rate for mode in modes if mode.refresh_rate is not None]
        + [float(value) for value in re.findall(r"(?i)(?:fps|refreshRate)\s*[=:]\s*(\d+(?:\.\d+)?)", display_text)]
    )
    active_match = re.search(
        r"(?i)(?:activeModeId|mActiveModeId|modeId)\s*(?:[=:]\s*|\s+)(\d+)",
        display_text,
    )
    hdr_match = re.search(r"(?i)(?:mSupportedHdrTypes|hdrTypes)\s*[=:]\s*\[([^]]*)\]", display_text)
    hdr_types = _unique_strings(
        value.strip() for value in (hdr_match.group(1).split(",") if hdr_match else []) if value.strip()
    )
    wide_match = re.search(
        r"(?i)(?:wideColorGamut|isWideColorGamut|wide_color)\s*[=:]\s*(true|false)",
        display_text,
    )
    display_ids = _unique_strings(
        match.group(1)
        for match in re.finditer(r"(?i)(?:mDisplayId|displayId)\s*[=: ]\s*(\d+)", combined)
    )
    service_missing = "can't find service" in combined.lower() or "service not found" in combined.lower()
    display_count = len(display_ids) or (
        1 if not service_missing and (display_text.strip() or window_displays_text.strip()) else None
    )
    return DisplayInfo(
        physical_size=physical_size,
        override_size=override_size,
        physical_density=physical_density,
        override_density=override_density,
        logical_width=logical_width,
        logical_height=logical_height,
        refresh_rates=refresh_rates,
        active_mode=active_match.group(1) if active_match else None,
        supported_modes=modes,
        hdr_types=hdr_types,
        wide_color_support=_parse_bool(wide_match.group(1)) if wide_match else None,
        display_count=display_count,
    )


def parse_telephony_info(
    properties: dict[str, str],
    registry_text: str,
    subscriptions_text: str,
    telecom_text: str,
) -> TelephonyInfo:
    """Parse non-identifier telephony inventory from properties and dumpsys text."""

    sim_states = _property_values(properties, ("gsm.sim.state",))
    network_types = _unique_strings(
        [*_property_values(properties, ("gsm.network.type",)), *_regex_values(
            registry_text, r"(?i)(?:mDataNetworkType|dataNetworkType|mVoiceNetworkType|voiceNetworkType)\s*[=:]\s*([A-Za-z0-9_]+)"
        )]
    )
    operator_alpha = _unique_strings(
        [*_property_values(properties, ("gsm.operator.alpha",)), *_regex_values(
            registry_text, r"(?i)mOperatorAlpha(?:Long|Short)?\s*[=:]\s*([^\s,]+)"
        )]
    )
    operator_numeric = _unique_strings(
        [*_property_values(properties, ("gsm.operator.numeric",)), *_regex_values(
            registry_text, r"(?i)mOperatorNumeric\s*[=:]\s*(\d{3,})"
        )]
    )
    operator_country_iso = _unique_strings(
        [*_property_values(properties, ("gsm.operator.iso-country",)), *_regex_values(
            registry_text, r"(?i)(?:operatorCountryIso|operator-iso-country)\s*[=:]\s*([A-Za-z]{2})"
        )]
    )
    roaming = _unique_bools(
        [
            *_parse_bool_values(_property_values(properties, ("gsm.operator.isroaming",))),
            *_parse_bool_values(_regex_values(registry_text, r"(?i)mIsRoaming\s*[=:]\s*(true|false)")),
        ]
    )
    phone_match = re.search(r"(?im)(?:mNumPhones|mPhoneCount|phoneCount|Phone Count)\s*[=:]\s*(\d+)", registry_text)
    phone_count = int(phone_match.group(1)) if phone_match else _derived_phone_count(registry_text)
    subscription_count = _parse_subscription_count(subscriptions_text, telecom_text)
    baseband = _first_property(properties, ("gsm.version.baseband", "ro.boot.baseband", "ro.baseband"))
    ril_implementation = _first_property(
        properties,
        ("ro.telephony.ril_impl", "ro.telephony.ril.v3", "persist.vendor.radio.ril_impl"),
    )
    radio_properties = {
        key: value
        for key, value in properties.items()
        if any(token in key.lower() for token in ("gsm.", "radio.", "ril"))
        and not any(token in key.lower() for token in ("imei", "imsi", "iccid", "subscriber", "phone", "msisdn"))
    }
    return TelephonyInfo(
        phone_count=phone_count,
        sim_states=sim_states,
        network_types=network_types,
        operator_alpha=operator_alpha,
        operator_numeric=operator_numeric,
        operator_country_iso=operator_country_iso,
        roaming=roaming,
        subscription_count=subscription_count,
        baseband=baseband,
        ril_implementation=ril_implementation,
        radio_properties=radio_properties,
    )


def parse_package_info(
    package_name: str,
    path_text: str,
    dumpsys_text: str,
    *,
    path_stderr: str = "",
    dumpsys_stderr: str = "",
) -> PackageInfo:
    """Parse bounded package metadata while excluding resolver-table details."""

    combined = f"{path_text}\n{dumpsys_text}\n{path_stderr}\n{dumpsys_stderr}"
    lower = combined.lower()
    path_lines = [line.strip() for line in path_text.splitlines() if line.strip()]
    package_paths = [
        line.removeprefix("package:").strip()
        for line in path_lines
        if line.startswith("package:")
    ]
    code_paths = _unique_strings(
        package_paths or _regex_values(dumpsys_text, r"(?im)^\s*codePath\s*=\s*([^\r\n]+)")
    )
    absent = any(marker in lower for marker in ("unknown package", "unable to find package", "package not found"))
    installed = True if code_paths or re.search(rf"(?i)Package\s*\[{re.escape(package_name)}\]", dumpsys_text) else None
    if absent:
        installed = False
    version_code = _parse_int_field(dumpsys_text, "versionCode")
    min_sdk = _parse_int_field(dumpsys_text, "minSdk")
    target_sdk = _parse_int_field(dumpsys_text, "targetSdk")
    version_name = _first_match(dumpsys_text, r"(?im)versionName\s*=\s*([^\s\r\n]+)")
    installer = _first_match(dumpsys_text, r"(?im)installerPackageName\s*=\s*([^\s\r\n]+)")
    first_install_time = _first_match(dumpsys_text, r"(?im)firstInstallTime\s*=\s*([^\r\n]+)")
    last_update_time = _first_match(dumpsys_text, r"(?im)lastUpdateTime\s*=\s*([^\r\n]+)")
    flags = " ".join(_regex_values(dumpsys_text, r"(?im)(?:privateFlags|flags)\s*=\s*\[([^]]*)\]"))
    return PackageInfo(
        package_name=package_name,
        installed=installed,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        first_install_time=first_install_time.strip() if first_install_time else None,
        last_update_time=last_update_time.strip() if last_update_time else None,
        installer_package_name=installer,
        code_paths=code_paths,
        enabled=_parse_labeled_bool(dumpsys_text, "enabled"),
        stopped=_parse_labeled_bool(dumpsys_text, "stopped"),
        suspended=_parse_labeled_bool(dumpsys_text, "suspended"),
        system_app=True if " SYSTEM " in f" {flags} " else False if flags else None,
        privileged_app=True if " PRIVILEGED " in f" {flags} " else False if flags else None,
        debuggable=True if " DEBUGGABLE " in f" {flags} " else False if flags else None,
        signing_certificate_digests=_unique_strings(
            value.replace(":", "").upper()
            for value in re.findall(
                r"(?i)(?:SHA-?256(?:\s+(?:digest|certificate))?|certificate(?:Digest|\s+digest)|signingCertificateDigest)\s*[:=]\s*([0-9a-f:]{16,})",
                dumpsys_text,
            )
        ),
    )


def parse_magisk_info(
    su_path_text: str,
    root_id_text: str,
    version_text: str,
    version_code_text: str,
    path_text: str,
    settings_text: str,
    modules_text: str,
    cloud_property_text: str,
) -> MagiskInfo:
    """Parse root-gated Magisk inventory without reading module contents."""

    uid_match = re.search(r"\buid=(\d+)", root_id_text)
    root_uid = int(uid_match.group(1)) if uid_match else None
    context_match = re.search(r"\bcontext=([^\s]+)", root_id_text)
    version_value = _clean_error_text(version_text)
    installed = bool(version_value) and not any(marker in version_value.lower() for marker in ("not found", "permission denied"))
    settings: dict[str, str] = {}
    for line in settings_text.splitlines():
        match = re.match(r"\s*([A-Za-z][A-Za-z0-9_.-]*)\s*[|=:]\s*(.*?)\s*$", line)
        if match:
            settings[match.group(1).lower()] = match.group(2)
    modules = _unique_strings(
        line.strip()
        for line in modules_text.splitlines()
        if line.strip() and "permission denied" not in line.lower() and "not found" not in line.lower()
    )
    return MagiskInfo(
        root_available=root_uid == 0,
        root_uid=root_uid,
        root_context=context_match.group(1) if context_match else None,
        magisk_installed=installed,
        magisk_version=version_value or None,
        magisk_version_code=_parse_optional_int(version_code_text),
        magisk_path=_clean_error_text(path_text) or None,
        zygisk_setting=settings.get("zygisk"),
        denylist_setting=settings.get("denylist"),
        module_names=modules,
        cloud_magisk_property=cloud_property_text.strip() or None,
    )


def parse_runtime_markers(
    mount_text: str,
    proc_mounts_text: str,
    processes_text: str,
    services_text: str,
    debug_ramdisk_text: str,
    data_adb_text: str,
    data_adb_modules_text: str,
    data_adb_magisk_text: str,
) -> RuntimeMarkers:
    """Inventory bounded runtime markers without assigning security conclusions."""

    mount_points = _unique_strings(
        match.group(1)
        for match in re.finditer(r"\bon\s+(/[^\s]+)\s+type\s+", f"{mount_text}\n{proc_mounts_text}")
    )
    process_names = _unique_strings(
        name
        for name in ("madbd", "process_daemon", "deviceservice", "fileservice", "screen_snap", "xu_daemon", "armcloud", "vmos")
        if re.search(rf"(?i)(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", processes_text)
    )
    service_names = _unique_strings(
        name
        for name in ("fileservice", "screen_snap", "deviceservice", "armcloud", "vmos")
        if re.search(rf"(?i)(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", services_text)
    )
    markers = set(process_names) | set(service_names)
    if debug_ramdisk_text.strip() and "permission denied" not in debug_ramdisk_text.lower():
        markers.add("/debug_ramdisk")
    if data_adb_text.strip() and "permission denied" not in data_adb_text.lower():
        markers.add("/data/adb")
    if data_adb_modules_text.strip() and "permission denied" not in data_adb_modules_text.lower():
        markers.add("/data/adb/modules")
    if data_adb_magisk_text.strip() and "permission denied" not in data_adb_magisk_text.lower():
        markers.add("/data/adb/magisk")
    marker_order = (
        "/debug_ramdisk",
        "/data/adb",
        "/data/adb/magisk",
        "/data/adb/modules",
        "deviceservice",
        "fileservice",
        "madbd",
        "process_daemon",
        "screen_snap",
        "xu_daemon",
        "armcloud",
        "vmos",
    )
    return RuntimeMarkers(
        markers=tuple(marker for marker in marker_order if marker in markers),
        mount_points=mount_points,
        process_names=process_names,
        service_names=service_names,
    )


def _parse_display_size(text: str, label: str) -> str | None:
    match = re.search(rf"(?i)\b{label}\s+size\s*:\s*(\d+)\s*x\s*(\d+)", text)
    return f"{match.group(1)}x{match.group(2)}" if match else None


def _parse_display_density(text: str, label: str) -> int | None:
    match = re.search(rf"(?i)\b{label}\s+density\s*:\s*(\d+)", text)
    return int(match.group(1)) if match else None


def _parse_logical_size(text: str) -> tuple[int | None, int | None]:
    match = re.search(r"(?i)logicalWidth\s*[=:]\s*(\d+).*?logicalHeight\s*[=:]\s*(\d+)", text)
    if match:
        return int(match.group(1)), int(match.group(2))
    match = re.search(r"(?i)\bw\s*=\s*(\d+)\s+h\s*=\s*(\d+)", text)
    return (int(match.group(1)), int(match.group(2))) if match else (None, None)


def _parse_display_modes(text: str) -> tuple[DisplayMode, ...]:
    modes: list[DisplayMode] = []
    pattern = re.compile(
        r"(?i)(?:Display\.Mode\s*\{|\{)?[^{}\n]*?\b(?:id|modeId)\s*[=:]\s*(\d+)"
        r"[^{}\n]*?\b(?:width|w)\s*[=:]\s*(\d+)"
        r"[^{}\n]*?\b(?:height|h)\s*[=:]\s*(\d+)"
        r"[^{}\n]*?\b(?:fps|refreshRate)\s*[=:]\s*(\d+(?:\.\d+)?)"
    )
    for match in pattern.finditer(text):
        modes.append(
            DisplayMode(
                mode_id=match.group(1),
                width=int(match.group(2)),
                height=int(match.group(3)),
                refresh_rate=float(match.group(4)),
            )
        )
    return tuple(modes)


def _property_values(properties: dict[str, str], names: tuple[str, ...]) -> tuple[str, ...]:
    values: list[str] = []
    for name in names:
        for value in properties.items():
            if value[0].lower() == name.lower():
                values.extend(part.strip() for part in value[1].split(",") if part.strip())
    return _unique_strings(values)


def _first_property(properties: dict[str, str], names: tuple[str, ...]) -> str | None:
    values = _property_values(properties, names)
    return values[0] if values else None


def _regex_values(text: str, pattern: str) -> list[str]:
    return [match.group(1).strip() for match in re.finditer(pattern, text) if match.group(1).strip()]


def _parse_bool(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def _parse_bool_values(values: tuple[str, ...] | list[str]) -> list[bool]:
    return [parsed for value in values if (parsed := _parse_bool(value)) is not None]


def _parse_labeled_bool(text: str, label: str) -> bool | None:
    match = re.search(rf"(?im)\b{re.escape(label)}\s*=\s*(true|false|0|1)\b", text)
    return _parse_bool(match.group(1)) if match else None


def _derived_phone_count(text: str) -> int | None:
    ids = [int(value) for value in re.findall(r"(?i)(?:Phone Id|phoneId)\s*[=:]\s*(\d+)", text)]
    return max(ids) + 1 if ids else None


def _parse_subscription_count(subscriptions_text: str, telecom_text: str) -> int | None:
    if re.search(r"(?i)ActiveSubInfoList\s*=\s*\[\s*\]", subscriptions_text):
        return 0
    info_count = len(re.findall(r"(?i)SubscriptionInfo\s*\{", subscriptions_text))
    if info_count:
        return info_count
    match = re.search(r"(?i)(?:Active subscriptions|subscription count)\s*[:=]\s*(\d+)", subscriptions_text)
    if match:
        return int(match.group(1))
    telecom_count = len(re.findall(r"(?i)PhoneAccountHandle\s*\{", telecom_text))
    return telecom_count or None


def _parse_int_field(text: str, label: str) -> int | None:
    match = re.search(rf"(?im)\b{re.escape(label)}\s*=\s*(\d+)", text)
    return int(match.group(1)) if match else None


def _parse_optional_int(text: str) -> int | None:
    match = re.search(r"\b(\d+)\b", text)
    return int(match.group(1)) if match else None


def _first_match(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else None


def _clean_error_text(text: str) -> str:
    value = text.strip()
    if not value or any(marker in value.lower() for marker in ("not found", "permission denied", "can't find")):
        return ""
    return value.splitlines()[0].strip()


def _unique_strings(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(str(value))
    return tuple(result)


def _unique_floats(values: list[float]) -> tuple[float, ...]:
    return tuple(sorted(set(values)))


def _unique_bools(values: list[bool]) -> tuple[bool, ...]:
    return tuple(dict.fromkeys(values))

_MAX_CAMERA_SUMMARY = 16
_MAX_SENSOR_SUMMARY = 64
_MAX_HAL_SUMMARY = 128
_CAMERA_HEADER_PATTERN = re.compile(
    r"(?im)^\s*(?:camera\s+(?:id|device(?:\s+id)?)|device\s+id)\s*[:=]\s*([^\s|]+)"
)
_CAMERA_DEVICE_HEADER_PATTERN = re.compile(r"(?im)^\s*==\s*camera\s+device\s+([^\s]+)")
_HIDL_DESCRIPTOR_PATTERN = re.compile(
    r"(?P<package>(?:android|vendor)\.[A-Za-z0-9_.]+)@(?P<version>\d+\.\d+)::"
    r"(?P<interface>I[A-Za-z0-9_]+)(?:/(?P<instance>[A-Za-z0-9_.:/-]+))?"
)
_AIDL_DESCRIPTOR_PATTERN = re.compile(
    r"(?P<descriptor>(?:android|vendor)\.[A-Za-z0-9_.]+\.I[A-Za-z0-9_]+)"
    r"(?:/(?P<instance>[A-Za-z0-9_.:/-]+))?"
)
_KNOWN_CAMERA_CAPABILITIES = {
    "BACKWARD_COMPATIBLE",
    "MANUAL_SENSOR",
    "MANUAL_POST_PROCESSING",
    "RAW",
    "PRIVATE_REPROCESSING",
    "READ_SENSOR_SETTINGS",
    "BURST_CAPTURE",
    "DEPTH_OUTPUT",
    "CONSTRAINED_HIGH_SPEED_VIDEO",
    "LOGICAL_MULTI_CAMERA",
    "ULTRA_HIGH_RESOLUTION_SENSOR",
    "MONOCHROME",
}
_SENSOR_TYPE_NAMES = {
    1: "accelerometer",
    2: "magnetic field",
    3: "orientation",
    4: "gyroscope",
    5: "light",
    6: "pressure",
    8: "proximity",
    9: "gravity",
    10: "linear acceleration",
    11: "rotation vector",
    12: "relative humidity",
    13: "ambient temperature",
    14: "uncalibrated magnetic field",
    15: "game rotation vector",
    16: "uncalibrated gyroscope",
    17: "significant motion",
    18: "step detector",
    19: "step counter",
    20: "geomagnetic rotation vector",
    21: "heart rate",
    28: "pose 6dof",
    29: "stationary detect",
    30: "motion detect",
    31: "heart beat",
    34: "low latency offbody detect",
    35: "accelerometer uncalibrated",
    36: "hinge angle",
    37: "head tracker",
}

def parse_camera_info(
    media_camera_text: str,
    cmd_list_text: str = "",
    cmd_dump_text: str = "",
) -> CameraInventory:
    """Parse bounded camera-service inventory across Android output variants."""

    combined = "\n".join((media_camera_text, cmd_list_text, cmd_dump_text))
    blocks = _camera_blocks("\n".join((media_camera_text, cmd_dump_text)))
    ids = list(blocks)
    for camera_id in _camera_ids_from_list(cmd_list_text):
        if camera_id not in ids:
            ids.append(camera_id)
            blocks[camera_id] = ""
    ids.sort(key=_natural_sort_key)
    cameras = tuple(_parse_camera_device(camera_id, blocks[camera_id]) for camera_id in ids)
    count_hint = _first_integer(combined, r"(?:number of|total)\s+camera(?: devices?)?\s*[:=]\s*(\d+)")
    camera_count = max(len(ids), count_hint or 0)
    combinations = _parse_camera_combinations(combined)
    active_client_count = _first_integer(
        combined,
        r"(?i)active\s+(?:camera\s+)?clients?\s*[:=]\s*(\d+)",
    )
    if active_client_count is None and re.search(r"(?i)active camera clients?", combined):
        active_client_count = len(re.findall(r"(?im)^\s*(?:client|pid)\b", combined))
    providers = _unique_strings(
        match.group(1).strip()
        for match in re.finditer(r"(?im)^\s*(?:provider(?: name)?|camera provider)\s*[:=]\s*(.+)$", combined)
    )
    versions = _unique_strings(
        match.group(1).strip()
        for match in re.finditer(r"(?im)^\s*(?:device|interface)\s+version\s*[:=]\s*(.+)$", combined)
    )
    warnings: list[str] = []
    if combined.strip() and not ids:
        warnings.append("no camera IDs parsed")
    if len(ids) > _MAX_CAMERA_SUMMARY:
        warnings.append(f"camera summary truncated to {_MAX_CAMERA_SUMMARY} items")
    if len(combinations) > _MAX_CAMERA_SUMMARY:
        warnings.append(f"camera combinations truncated to {_MAX_CAMERA_SUMMARY} items")
    return CameraInventory(
        camera_count=camera_count,
        logical_camera_count=sum(
            bool(camera.physical_ids) or "LOGICAL_MULTI_CAMERA" in camera.capability_names
            for camera in cameras
        ),
        physical_camera_count=len(
            {physical_id for camera in cameras for physical_id in camera.physical_ids}
        ),
        cameras=cameras[:_MAX_CAMERA_SUMMARY],
        concurrent_combinations=combinations[:_MAX_CAMERA_SUMMARY],
        active_client_count=active_client_count,
        service_status=_camera_service_status(combined),
        provider_names=providers[:_MAX_CAMERA_SUMMARY],
        device_versions=versions[:_MAX_CAMERA_SUMMARY],
        parse_warnings=tuple(warnings),
    )

def parse_sensor_info(text: str) -> SensorInventory:
    """Parse sensorservice inventory without activating or sampling sensors."""

    blocks = _sensor_blocks(text)
    warnings: list[str] = []
    sensors: list[SensorDevice] = []
    for handle, block in blocks:
        sensor, sensor_warnings = _parse_sensor_device(handle, block)
        sensors.append(sensor)
        warnings.extend(sensor_warnings)
    sensors.sort(key=lambda sensor: _natural_sort_key(sensor.handle))
    if text.strip() and not sensors:
        warnings.append("no sensor entries parsed")
    if len(sensors) > _MAX_SENSOR_SUMMARY:
        warnings.append(f"sensor summary truncated to {_MAX_SENSOR_SUMMARY} items")
    type_counts: Counter[str] = Counter()
    vendor_counts: Counter[str] = Counter()
    for sensor in sensors:
        type_counts[sensor.string_type or sensor.normalized_type] += 1
        if sensor.vendor:
            vendor_counts[sensor.vendor] += 1
    active_sensor_count = _first_integer(text, r"(?i)active\s+sensors?\s*[:=]\s*(\d+)")
    active_connection_count = _first_integer(text, r"(?i)active\s+connections?\s*[:=]\s*(\d+)")
    return SensorInventory(
        sensor_count=len(sensors),
        sensors=tuple(sensors[:_MAX_SENSOR_SUMMARY]),
        type_counts=dict(sorted(type_counts.items())),
        vendor_counts=dict(sorted(vendor_counts.items())),
        wakeup_sensor_count=sum(sensor.wake_up is True for sensor in sensors),
        dynamic_sensor_count=sum(sensor.dynamic is True for sensor in sensors),
        active_sensor_count=active_sensor_count,
        active_connection_count=active_connection_count,
        service_status=_sensor_service_status(text),
        parse_warnings=tuple(dict.fromkeys(warnings)),
    )

def parse_hal_info(
    lshal_text: str,
    lshal_interfaces_text: str = "",
    dumpsys_services_text: str = "",
    service_list_text: str = "",
    properties: Mapping[str, str] | None = None,
) -> HalInventory:
    """Parse HIDL, AIDL, binderized, passthrough, and lazy HAL inventory."""

    candidates: dict[tuple[str, str | None], HalInterface] = {}
    for source, text in (
        ("lshal", lshal_text),
        ("lshal_interfaces", lshal_interfaces_text),
        ("dumpsys_services", dumpsys_services_text),
    ):
        for line in text.splitlines():
            for item in _hal_items_from_line(line, source):
                key = (item.full_interface, item.instance)
                previous = candidates.get(key)
                if previous is None or _hal_item_score(item) > _hal_item_score(previous):
                    candidates[key] = item
    interfaces = tuple(
        sorted(candidates.values(), key=lambda item: (item.family, item.full_interface, item.instance or ""))
    )
    warnings: list[str] = []
    combined = "\n".join((lshal_text, lshal_interfaces_text, dumpsys_services_text))
    if combined.strip() and not interfaces:
        warnings.append("no HAL interfaces parsed")
    if len(interfaces) > _MAX_HAL_SUMMARY:
        warnings.append(f"HAL summary truncated to {_MAX_HAL_SUMMARY} items")
    binder_services = _service_names(service_list_text)
    dumpsys_services = _service_names(dumpsys_services_text)
    hal_properties = {
        key: value
        for key, value in sorted((properties or {}).items())
        if "hal" in key.lower() or key.lower().startswith("ro.hardware")
    }
    bounded_properties = dict(list(hal_properties.items())[:32])
    return HalInventory(
        hal_count=len(interfaces),
        hidl_count=sum("@" in item.full_interface and "::" in item.full_interface for item in interfaces),
        aidl_count=sum("@" not in item.full_interface for item in interfaces),
        passthrough_count=sum(item.transport == "passthrough" for item in interfaces),
        binderized_count=sum(item.transport in {"binder", "hwbinder", "vndbinder"} for item in interfaces),
        lazy_count=sum(item.service_state == "lazy" for item in interfaces),
        families=_unique_strings(item.family for item in interfaces),
        interfaces=interfaces[:_MAX_HAL_SUMMARY],
        binder_service_count=len(binder_services),
        dumpsys_service_count=len(dumpsys_services),
        hal_properties=bounded_properties,
        parse_warnings=tuple(dict.fromkeys(warnings)),
    )

def _camera_blocks(text: str) -> dict[str, str]:
    matches = list(_CAMERA_HEADER_PATTERN.finditer(text))
    matches.extend(_CAMERA_DEVICE_HEADER_PATTERN.finditer(text))
    matches.sort(key=lambda match: match.start())
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        camera_id = match.group(1).strip("'\"")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result[camera_id] = f"{result.get(camera_id, '')}\n{text[match.end():end]}"
    return result

def _camera_ids_from_list(text: str) -> tuple[str, ...]:
    ids: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        match = re.search(r"(?i)(?:camera\s+(?:id|device)|id)\s*[:=]\s*([A-Za-z0-9_.:-]+)", stripped)
        if match:
            ids.append(match.group(1))
        elif re.fullmatch(r"[0-9A-Za-z_.:-]+", stripped) and stripped not in {"camera", "devices"}:
            ids.append(stripped)
    return _unique_strings(ids)

def _parse_camera_device(camera_id: str, text: str) -> CameraDevice:
    facing = (_first_match(text, r"(?im)^\s*facing\s*[:=]\s*(front|back|external|unknown)") or "unknown").lower()
    facing_value = _first_integer(text, r"(?i)(?:lens\.facing|facing)[^\n]*?\[\s*(\d+)\s*\]")
    if facing_value is not None:
        facing = {0: "front", 1: "back", 2: "external"}.get(facing_value, facing)
    hardware = _first_match(text, r"(?im)^\s*(?:hardware(?: support)? level|supported hardware level)\s*[:=]\s*([A-Za-z0-9_-]+)")
    if hardware is None:
        hardware = _first_match(text, r"(?i)supportedHardwareLevel[\s\S]{0,120}?\[\s*(\d+)\s*\]")
    hardware_level = _normalize_hardware_level(hardware)
    capabilities = _camera_capabilities(text)
    physical_ids = _camera_physical_ids(text)
    sizes = _unique_strings(
        size
        for line in text.splitlines()
        if re.search(r"(?i)size|stream|output", line)
        for size in re.findall(r"\b\d{2,5}x\d{2,5}\b", line)
    )
    format_values = [
        value
        for match in re.finditer(
            r"(?im)^\s*(?:output\s+formats?|formats?)\s*[:=]\s*([^\n]+)",
            text,
        )
        for value in re.split(r"[,\s]+", match.group(1).strip())
        if value and value.lower() not in {"none", "unknown"}
    ]
    format_values.extend(
        match.group(1)
        for match in re.finditer(r"(?i)\bformat\s*=\s*([A-Za-z0-9_.-]+)", text)
    )
    formats = _unique_strings(format_values)
    format_count = len(formats)
    if format_count == 0:
        format_count = len(
            re.findall(r"(?i)(?:stream configurations?|format)\s*[:=]", text)
        )
    return CameraDevice(
        id=camera_id,
        facing=facing,
        orientation=_first_integer(text, r"(?im)(?:sensor\.)?orientation\s*[:=]\s*(-?\d+)")
        or _first_integer(text, r"(?i)sensor\.orientation[^\n]*?\[\s*(-?\d+)\s*\]"),
        hardware_level=hardware_level,
        physical_ids=physical_ids,
        flash_available=_first_bool(text, r"(?im)(?:flash(?: available|availability)?|flash\.info\.available)\s*[:=]\s*(true|false)")
        if re.search(r"(?im)(?:flash(?: available|availability)?|flash\.info\.available)\s*[:=]", text)
        else None,
        capability_names=capabilities,
        output_format_count=format_count,
        representative_output_sizes=sizes[:8],
        fps_ranges=_camera_fps_ranges(text),
        provider_name=_first_match(text, r"(?im)^\s*(?:provider(?: name)?|camera provider)\s*[:=]\s*(.+)$"),
        device_version=_first_match(text, r"(?im)^\s*(?:device|interface)\s+version\s*[:=]\s*(.+)$"),
    )

def _normalize_hardware_level(value: str | None) -> str:
    normalized = (value or "").strip().upper().replace("-", "_")
    numeric = {"0": "LIMITED", "1": "FULL", "2": "LEGACY", "3": "LEVEL_3", "4": "EXTERNAL"}
    return numeric.get(normalized, normalized if normalized in {"LEGACY", "LIMITED", "FULL", "LEVEL_3", "EXTERNAL"} else "UNKNOWN")

def _camera_capabilities(text: str) -> tuple[str, ...]:
    values: list[str] = []
    for line in text.splitlines():
        if "capabil" not in line.lower():
            continue
        for value in re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", line.upper()):
            if value in _KNOWN_CAMERA_CAPABILITIES and value not in values:
                values.append(value)
    return tuple(sorted(values))

def _camera_physical_ids(text: str) -> tuple[str, ...]:
    match = re.search(r"(?im)^\s*(?:physical(?: camera)? ids?|physical_ids?)\s*[:=]\s*(.+)$", text)
    if not match:
        return ()
    return _unique_strings(
        value.strip("[](){}'\"")
        for value in re.split(r"[,\s]+", match.group(1))
        if value.strip("[](){}'\"").lower() not in {"none", "null"}
    )

def _camera_fps_ranges(text: str) -> tuple[tuple[int, int], ...]:
    values: set[tuple[int, int]] = set()
    for line in text.splitlines():
        if not re.search(r"(?i)fps|frame rate|target", line):
            continue
        for first, second in re.findall(r"[\[(]\s*(\d+)\s*[,x/]\s*(\d+)\s*[\])]", line):
            values.add((int(first), int(second)))
    return tuple(sorted(values))[:8]

def _parse_camera_combinations(text: str) -> tuple[tuple[str, ...], ...]:
    combinations: set[tuple[str, ...]] = set()
    for line in text.splitlines():
        if "concurrent" not in line.lower():
            continue
        for group in re.findall(r"[({[]([^(){}[]+)[)}]", line):
            ids = tuple(sorted(_unique_strings(re.findall(r"[A-Za-z0-9_.:-]+", group)), key=_natural_sort_key))
            if len(ids) > 1:
                combinations.add(ids)
    return tuple(sorted(combinations))

def _camera_service_status(text: str) -> str | None:
    if not text.strip():
        return None
    lower = text.lower()
    if any(
        marker in lower
        for marker in (
            "can't find service",
            "service not found",
            "unavailable",
            "not available",
            "permission denial",
            "permission denied",
            "security exception",
        )
    ):
        return "unavailable"
    if "camera" in lower:
        return "available"
    return "unknown"

def _sensor_blocks(text: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    current_handle: str | None = None
    current_lines: list[str] = []
    for line in text.splitlines():
        explicit = re.match(r"(?i)^\s*(?:handle\s*[:=]\s*|sensor\s+(?:handle\s*)?[:#=]\s*)(0x[0-9a-f]+|\d+)\b(.*)$", line)
        compact = re.match(r"^\s*(0x[0-9a-fA-F]+|\d+)\)\s*(.*)$", line)
        match = explicit or compact
        if match:
            if current_handle is not None:
                blocks.append((current_handle, "\n".join(current_lines)))
            current_handle = match.group(1)
            current_lines = [match.group(2)]
        elif current_handle is not None:
            current_lines.append(line)
    if current_handle is not None:
        blocks.append((current_handle, "\n".join(current_lines)))
    return blocks

def _parse_sensor_device(handle: str, text: str) -> tuple[SensorDevice, list[str]]:
    warnings: list[str] = []
    name = _sensor_field(text, ("name", "sensor name")) or text.split("|", 1)[0].strip() or "unknown"
    vendor = _sensor_field(text, ("vendor",))
    version = _sensor_int(text, "version", warnings)
    type_value = _sensor_int(text, ("type", "type value"), warnings)
    string_type = _sensor_field(text, ("stringType", "string type"))
    normalized_type = _normalize_sensor_type(string_type, type_value)
    wake_up = _sensor_bool(text, ("wake-up", "wakeup", "wake up"))
    if wake_up is None and re.search(r"(?i)WAKE[_ -]?UP", text):
        wake_up = True
    dynamic = _sensor_bool(text, ("dynamic", "dynamic sensor"))
    return SensorDevice(
        handle=handle,
        name=name,
        vendor=vendor,
        version=version,
        type_value=type_value,
        string_type=string_type,
        normalized_type=normalized_type,
        reporting_mode=_sensor_field(text, ("reporting mode", "reportingMode", "mode")),
        wake_up=wake_up,
        dynamic=dynamic,
        maximum_range=_sensor_float(text, ("maxRange", "maximum range", "max range"), warnings),
        resolution=_sensor_float(text, ("resolution",), warnings),
        power=_sensor_float(text, ("power", "power usage"), warnings),
        minimum_delay=_sensor_int(text, ("minDelay", "minimum delay", "min delay"), warnings),
        maximum_delay=_sensor_int(text, ("maxDelay", "maximum delay", "max delay"), warnings),
        fifo_reserved_count=_sensor_int(text, ("fifoReserved", "FIFO reserved", "fifo reserved count"), warnings),
        fifo_maximum_count=_sensor_int(text, ("fifoMax", "FIFO max", "fifo maximum count"), warnings),
        required_permission=_sensor_field(text, ("permission", "required permission")),
    ), warnings

def _sensor_field(text: str, labels: tuple[str, ...]) -> str | None:
    for label in labels:
        match = re.search(rf"(?im)(?:^|[|,])\s*{re.escape(label)}\s*[:=]\s*([^|,\n]+)", text)
        if match:
            return match.group(1).strip()
    return None

def _sensor_int(text: str, labels: str | tuple[str, ...], warnings: list[str]) -> int | None:
    labels_tuple = (labels,) if isinstance(labels, str) else labels
    value = _sensor_field(text, labels_tuple)
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        warnings.append(f"invalid integer for {labels_tuple[0]}")
        return None

def _sensor_float(text: str, labels: tuple[str, ...], warnings: list[str]) -> float | None:
    value = _sensor_field(text, labels)
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        warnings.append(f"invalid number for {labels[0]}")
        return None

def _sensor_bool(text: str, labels: tuple[str, ...]) -> bool | None:
    value = _sensor_field(text, labels)
    if value is None:
        return None
    return value.strip().lower() in {"1", "true", "yes", "on", "wakeup", "wake-up"}

def _normalize_sensor_type(string_type: str | None, type_value: int | None) -> str:
    if string_type:
        normalized = string_type.strip()
        if normalized.startswith("android.sensor."):
            return normalized.removeprefix("android.sensor.").replace("_", " ")
        return normalized
    if type_value is None:
        return "unknown vendor-specific type"
    return _SENSOR_TYPE_NAMES.get(type_value, f"unknown vendor-specific type {type_value}")

def _sensor_service_status(text: str) -> str | None:
    if not text.strip():
        return None
    lower = text.lower()
    if any(marker in lower for marker in ("permission denial", "permission denied", "can't find service", "not found")):
        return "unavailable"
    return "available" if "sensor" in lower else "unknown"

def _hal_items_from_line(line: str, source: str) -> tuple[HalInterface, ...]:
    items: list[HalInterface] = []
    for match in _HIDL_DESCRIPTOR_PATTERN.finditer(line):
        package = match.group("package")
        items.append(_make_hal_item(
            family=_hal_family(package),
            full_interface=f"{package}@{match.group('version')}::{match.group('interface')}",
            version=match.group("version"),
            instance=match.group("instance"),
            line=line,
            source=source,
        ))
    if not items:
        for match in _AIDL_DESCRIPTOR_PATTERN.finditer(line):
            descriptor = match.group("descriptor")
            package = descriptor.rsplit(".", 1)[0]
            items.append(_make_hal_item(
                family=_hal_family(package),
                full_interface=descriptor,
                version=None,
                instance=match.group("instance"),
                line=line,
                source=source,
            ))
    return tuple(items)

def _make_hal_item(
    *,
    family: str,
    full_interface: str,
    version: str | None,
    instance: str | None,
    line: str,
    source: str,
) -> HalInterface:
    lower = line.lower()
    transport = next(
        (value for value in ("passthrough", "hwbinder", "vndbinder", "binder") if value in lower),
        "binder" if source == "dumpsys_services" else "unknown",
    )
    state = "lazy" if "lazy" in lower else "running" if any(value in lower for value in ("running", "registered", "server")) else None
    pid_match = re.search(r"(?i)(?:server\s+)?pid\s*[:=]\s*(\d+)", line)
    client_pids = tuple(int(value) for value in re.findall(r"(?i)client(?:s)?(?: pid)?\s*[:=]\s*(\d+)", line))
    thread_match = re.search(r"(?i)threads?\s*[:=]\s*([^,|]+)", line)
    return HalInterface(
        family=family,
        full_interface=full_interface,
        version=version,
        instance=instance,
        transport=transport,
        architecture=_first_match(line, r"\b(32\+64|32|64)\s*(?:bit)?\b"),
        service_state=state,
        source=source,
        server_pid=int(pid_match.group(1)) if pid_match else None,
        client_pids=client_pids,
        thread_usage=thread_match.group(1).strip() if thread_match else None,
    )

def _hal_item_score(item: HalInterface) -> int:
    return (item.transport != "unknown") * 2 + (item.service_state is not None) + (item.architecture is not None)

def _hal_family(package: str) -> str:
    parts = package.split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else package

def _service_names(text: str) -> tuple[str, ...]:
    return _unique_strings(
        match.group(1)
        for match in re.finditer(r"(?im)^\s*(?:\d+\s+)?((?:android|vendor)\.[A-Za-z0-9_.]+)", text)
    )

def _first_integer(text: str, pattern: str) -> int | None:
    match = re.search(pattern, text)
    return int(match.group(1)) if match else None

def _first_bool(text: str, pattern: str) -> bool | None:
    match = re.search(pattern, text)
    return match.group(1).lower() in {"true", "1", "yes", "on"} if match else None

def _natural_sort_key(value: str) -> tuple[object, ...]:
    return tuple(int(part) if part.isdigit() else part for part in re.split(r"(\d+)", value))


_MAX_SYSTEM_SUMMARY = 32
_AUDIO_DIRECTION_VALUES = {"INPUT", "OUTPUT", "BIDIRECTIONAL", "UNKNOWN"}
_AUDIO_ROLE_VALUES = {"SOURCE", "SINK", "UNKNOWN"}
_BATTERY_STATUS_VALUES = {"UNKNOWN", "CHARGING", "DISCHARGING", "NOT_CHARGING", "FULL"}
_BATTERY_HEALTH_VALUES = {
    "UNKNOWN",
    "GOOD",
    "OVERHEAT",
    "DEAD",
    "OVER_VOLTAGE",
    "UNSPECIFIED_FAILURE",
    "COLD",
}
_THERMAL_SEVERITIES = {
    "NONE",
    "LIGHT",
    "MODERATE",
    "SEVERE",
    "CRITICAL",
    "EMERGENCY",
    "SHUTDOWN",
    "UNKNOWN",
}
_THERMAL_SENSOR_TYPES = {
    "CPU",
    "GPU",
    "BATTERY",
    "SKIN",
    "USB_PORT",
    "POWER_AMPLIFIER",
    "BCL_VOLTAGE",
    "BCL_CURRENT",
    "BCL_PERCENTAGE",
    "NPU",
    "MODEM",
    "SOC",
    "AMBIENT",
    "UNKNOWN",
}
_WAKEFULNESS_VALUES = {"AWAKE", "ASLEEP", "DREAMING", "DOZING", "UNKNOWN"}
_VOLUME_TYPES = {"PUBLIC", "PRIVATE", "EMULATED", "STUB", "ASEC", "OBB", "UNKNOWN"}
_VOLUME_STATES = {
    "UNMOUNTED",
    "CHECKING",
    "MOUNTED",
    "MOUNTED_READ_ONLY",
    "FORMATTING",
    "EJECTING",
    "UNMOUNTABLE",
    "REMOVED",
    "BAD_REMOVAL",
    "UNKNOWN",
}


def parse_audio_info(
    audio_text: str,
    flinger_text: str = "",
    policy_text: str = "",
    ports_text: str = "",
    patches_text: str = "",
) -> AudioInventory:
    """Parse bounded audio metadata without controlling media or routes."""

    combined = "\n".join((audio_text, flinger_text, policy_text, ports_text, patches_text))
    warnings: list[str] = []
    devices = _parse_audio_devices("\n".join((audio_text, policy_text, ports_text)), warnings)
    outputs = tuple(device for device in devices if device.direction in {"OUTPUT", "BIDIRECTIONAL"})
    inputs = tuple(device for device in devices if device.direction in {"INPUT", "BIDIRECTIONAL"})
    if combined.strip() and not devices and "audio" in combined.lower():
        warnings.append("no audio devices or ports parsed")
    if len(outputs) > _MAX_SYSTEM_SUMMARY or len(inputs) > _MAX_SYSTEM_SUMMARY:
        warnings.append(f"audio device summary truncated to {_MAX_SYSTEM_SUMMARY} items")
    return AudioInventory(
        service_status=_service_status(audio_text, "audio"),
        audio_server_status=_labeled_status(combined, "audio server"),
        audio_policy_status=_labeled_status(policy_text or audio_text, "audio policy"),
        current_mode=_bounded_text(_first_match(combined, r"(?im)^\s*(?:mode|audio mode)\s*[:=]\s*([^\r\n]+)")),
        master_muted=_first_bool(combined, r"(?im)^\s*(?:master mute|master_muted)\s*[:=]\s*(true|false|1|0)"),
        microphone_muted=_first_bool(combined, r"(?im)^\s*(?:mic(?:rophone)? mute|microphone_muted)\s*[:=]\s*(true|false|1|0)"),
        fixed_volume=_first_bool(combined, r"(?im)^\s*(?:fixed volume|fixed_volume)\s*[:=]\s*(true|false|1|0)"),
        communication_device=_bounded_text(_first_match(combined, r"(?im)^\s*(?:communication device|communication_device)\s*[:=]\s*([^\r\n]+)")),
        output_devices=outputs[:_MAX_SYSTEM_SUMMARY],
        input_devices=inputs[:_MAX_SYSTEM_SUMMARY],
        output_thread_count=_count_or_labeled(combined, "output threads"),
        input_thread_count=_count_or_labeled(combined, "input threads"),
        active_playback_client_count=_count_or_labeled(combined, "active playback clients"),
        active_recording_client_count=_count_or_labeled(combined, "active recording clients"),
        audio_focus_owner_count=_count_or_labeled(combined, "audio focus owners"),
        active_patch_count=_count_or_labeled(patches_text or combined, "(?:active )?audio patches"),
        effect_count=_count_or_labeled(flinger_text or combined, "(?:audio )?effects"),
        parse_warnings=_bounded_warnings(warnings),
    )


def parse_battery_info(
    battery_text: str,
    properties_text: str = "",
    command_values: Mapping[str, str] | None = None,
) -> BatteryInventory:
    """Parse battery values only when labels identify their source units."""

    command_values = command_values or {}
    combined = "\n".join((battery_text, properties_text))
    warnings: list[str] = []
    values = _battery_labeled_values(combined)
    for key, text in sorted(command_values.items()):
        value = text.strip()
        if not value:
            continue
        previous = values.get(key)
        if previous is not None and previous != value:
            warnings.append(f"conflicting battery value for {key}; dumpsys value retained")
            continue
        values.setdefault(key, value)
    level = _integer_value(values.get("level"))
    scale = _integer_value(values.get("scale"))
    level_percent = None
    if level is not None and scale is not None and scale > 0:
        level_percent = round(level * 100 / scale)
    elif level is not None and 0 <= level <= 100 and "level" in values:
        level_percent = level
    elif values.get("level"):
        warnings.append("battery level lacks usable scale")
    temperature_tenths = _temperature_tenths(values.get("temperature"), warnings)
    battery_status = _normalize_battery_status(values.get("status"))
    charging_value = _bool_value(values.get("charging"))
    if charging_value is None and battery_status in {"CHARGING", "DISCHARGING", "NOT_CHARGING", "FULL"}:
        charging_value = battery_status == "CHARGING"
    return BatteryInventory(
        battery_present=_bool_value(values.get("present")),
        battery_status=battery_status,
        battery_health=_normalize_battery_health(values.get("health")),
        plugged_source=_normalize_plugged(values.get("plugged"), values),
        charging=charging_value,
        level_percent=level_percent,
        scale=scale,
        voltage_mv=_unit_integer(values.get("voltage"), ("mv", "millivolt"), warnings, "voltage"),
        temperature_tenths_c=temperature_tenths,
        temperature_c=temperature_tenths / 10 if temperature_tenths is not None else None,
        current_now_ua=_unit_integer(values.get("current now"), ("ua", "microamp"), warnings, "current now"),
        current_average_ua=_unit_integer(values.get("current average"), ("ua", "microamp"), warnings, "current average"),
        charge_counter_uah=_unit_integer(values.get("charge counter"), ("uah", "microamp-hour"), warnings, "charge counter"),
        energy_counter_nwh=_unit_integer(values.get("energy counter"), ("nwh", "nanowatt-hour"), warnings, "energy counter"),
        max_charging_current_ua=_unit_integer(values.get("max charging current"), ("ua", "microamp"), warnings, "max charging current"),
        max_charging_voltage_uv=_unit_integer(values.get("max charging voltage"), ("uv", "microvolt"), warnings, "max charging voltage"),
        technology=_bounded_text(values.get("technology")),
        property_service_status=_service_status(properties_text, "battery"),
        parse_warnings=_bounded_warnings(warnings),
    )


def parse_thermal_info(
    thermal_text: str,
    power_text: str = "",
    idle_text: str = "",
    thermal_command_text: str = "",
    power_mode_text: str = "",
    fixed_performance_text: str = "",
) -> ThermalInventory:
    """Parse current thermal and power observations without performance conclusions."""

    combined_thermal = "\n".join((thermal_text, thermal_command_text))
    combined_power = "\n".join((power_text, idle_text, power_mode_text, fixed_performance_text))
    warnings: list[str] = []
    sensors = _parse_thermal_sensors(combined_thermal, warnings)
    cooling = _parse_cooling_devices(combined_thermal, warnings)
    if len(sensors) > _MAX_SYSTEM_SUMMARY or len(cooling) > _MAX_SYSTEM_SUMMARY:
        warnings.append(f"thermal summary truncated to {_MAX_SYSTEM_SUMMARY} items")
    return ThermalInventory(
        thermal_service_status=_service_status(combined_thermal, "thermal"),
        thermal_hal_status=_labeled_status(combined_thermal, "thermal hal"),
        current_thermal_severity=_normalize_severity(
            _first_match(combined_thermal, r"(?im)^\s*(?:current )?(?:thermal )?severity\s*[:=]\s*([^\r\n]+)")
        ),
        temperature_sensors=tuple(sensors[:_MAX_SYSTEM_SUMMARY]),
        cooling_devices=tuple(cooling[:_MAX_SYSTEM_SUMMARY]),
        power_service_status=_service_status(power_text, "power"),
        wakefulness=_normalize_wakefulness(_first_match(combined_power, r"(?im)^\s*wakefulness\s*[:=]\s*([^\r\n]+)")),
        interactive=_first_bool(combined_power, r"(?im)^\s*interactive\s*[:=]\s*(true|false|1|0)"),
        battery_saver_enabled=_first_bool(combined_power, r"(?im)^\s*(?:battery saver|battery_saver_enabled)\s*[:=]\s*(true|false|1|0)"),
        adaptive_power_saver_enabled=_first_bool(combined_power, r"(?im)^\s*(?:adaptive power saver|adaptive_power_saver_enabled)\s*[:=]\s*(true|false|1|0)"),
        fixed_performance_mode_enabled=_first_bool(combined_power, r"(?im)^\s*(?:fixed performance mode(?: enabled)?|fixed_performance_mode_enabled)\s*[:=]\s*(true|false|1|0)"),
        current_power_mode=_first_match(power_mode_text or combined_power, r"(?im)^\s*(?:mode|power mode)\s*[:=]?\s*([^\r\n]+)") or None,
        device_idle_mode=_first_bool(combined_power, r"(?im)^\s*(?:device )?idle mode\s*[:=]\s*(true|false|1|0)"),
        light_idle_mode=_first_bool(combined_power, r"(?im)^\s*light idle mode\s*[:=]\s*(true|false|1|0)"),
        active_wake_lock_count=_count_or_labeled(combined_power, "active wake ?locks"),
        suspend_blocker_count=_count_or_labeled(combined_power, "suspend blockers"),
        last_wake_reason=_bounded_text(_first_match(combined_power, r"(?im)^\s*last wake reason\s*[:=]\s*([^\r\n]+)")),
        last_sleep_reason=_bounded_text(_first_match(combined_power, r"(?im)^\s*last sleep reason\s*[:=]\s*([^\r\n]+)")),
        parse_warnings=_bounded_warnings(warnings),
    )


def parse_storage_info(
    df_text: str,
    mount_text: str = "",
    proc_mounts_text: str = "",
    filesystems_text: str = "",
    partitions_text: str = "",
    mount_service_text: str = "",
    volumes_text: str = "",
    disks_text: str = "",
    primary_uuid_text: str = "",
    properties: Mapping[str, str] | None = None,
) -> StorageInventory:
    """Parse a bounded read-only storage inventory without inferring device health."""

    warnings: list[str] = []
    mounts = _merge_mounts(
        _parse_df_mounts(df_text, warnings),
        _parse_mount_lines(mount_text, "storage.mount", warnings),
        _parse_mount_lines(proc_mounts_text, "storage.proc_mounts", warnings),
    )
    volumes = _parse_storage_volumes(volumes_text, warnings)
    filesystems = _parse_filesystems(filesystems_text)
    partitions = _parse_partitions(partitions_text, warnings)
    if len(mounts) > _MAX_SYSTEM_SUMMARY or len(volumes) > _MAX_SYSTEM_SUMMARY:
        warnings.append(f"storage summary truncated to {_MAX_SYSTEM_SUMMARY} items")
    props = properties or {}
    return StorageInventory(
        mounts=tuple(mounts[:_MAX_SYSTEM_SUMMARY]),
        volumes=tuple(volumes[:_MAX_SYSTEM_SUMMARY]),
        disk_count=_storage_disk_count(disks_text),
        partitions=tuple(partitions[:_MAX_SYSTEM_SUMMARY]),
        supported_filesystems=tuple(filesystems[:_MAX_SYSTEM_SUMMARY]),
        primary_storage_uuid_state=_primary_uuid_state(primary_uuid_text),
        mount_service_status=_service_status(mount_service_text, "mount"),
        encryption_state=_first_storage_property(props, ("ro.crypto.state", "ro.crypto.type")),
        metadata_encryption_state=_first_storage_property(
            props,
            ("ro.crypto.metadata.enabled", "ro.crypto.metadata.encryption"),
        ),
        parse_warnings=_bounded_warnings(warnings),
    )


def _parse_audio_devices(text: str, warnings: list[str]) -> tuple[AudioDevice, ...]:
    blocks = re.split(r"(?im)^\s*(?=(?:audio )?(?:device|port)\s*(?:id)?\s*[:=])", text)
    devices: list[AudioDevice] = []
    for block in blocks:
        identifier = _first_match(block, r"(?im)^\s*(?:audio )?(?:device|port)\s*(?:id)?\s*[:=]\s*([^\s,]+)")
        if not identifier:
            continue
        device_type = _first_match(block, r"(?im)^\s*(?:type|device type)\s*[:=]\s*([^\r\n,]+)")
        direction = _normalize_audio_direction(
            _first_match(block, r"(?im)^\s*(?:direction|io)\s*[:=]\s*([^\r\n,]+)")
            or device_type
        )
        role = _normalize_audio_role(_first_match(block, r"(?im)^\s*role\s*[:=]\s*([^\r\n,]+)"))
        if direction == "UNKNOWN" and device_type:
            warnings.append(f"unknown audio direction for {identifier}")
        devices.append(
            AudioDevice(
                id=_bounded_text(identifier, 80) or "unknown",
                role=role,
                direction=direction,
                device_type=_bounded_text(device_type.strip() if device_type else None, 128),
                address=_bounded_text(_first_match(block, r"(?im)^\s*address\s*[:=]\s*([^\r\n]+)")),
                product_name=_bounded_text(_first_match(block, r"(?im)^\s*(?:name|product name)\s*[:=]\s*([^\r\n]+)")),
                connected=_first_bool(block, r"(?im)^\s*connected\s*[:=]\s*(true|false|1|0)"),
                active=_first_bool(block, r"(?im)^\s*active\s*[:=]\s*(true|false|1|0)"),
                formats=_token_values(block, "formats?"),
                sample_rates=_integer_tokens(_token_values(block, "sample ?rates?")),
                channel_masks=_token_values(block, "channel masks?"),
                flags=_token_values(block, "flags?"),
                source="audio",
            )
        )
    return tuple(sorted(devices, key=lambda item: _natural_sort_key(item.id)))


def _battery_labeled_values(text: str) -> dict[str, str]:
    aliases = {
        "present": "present",
        "status": "status",
        "health": "health",
        "plugged": "plugged",
        "level": "level",
        "scale": "scale",
        "voltage": "voltage",
        "temperature": "temperature",
        "current now": "current now",
        "current average": "current average",
        "charge counter": "charge counter",
        "energy counter": "energy counter",
        "max charging current": "max charging current",
        "max charging voltage": "max charging voltage",
        "technology": "technology",
        "charging": "charging",
        "ac powered": "ac powered",
        "usb powered": "usb powered",
        "wireless powered": "wireless powered",
        "dock powered": "dock powered",
    }
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*([^:=]+?)\s*[:=]\s*(.*?)\s*$", line)
        if not match:
            continue
        label = re.sub(r"\s+", " ", match.group(1).strip().lower())
        if label in aliases and match.group(2):
            values[aliases[label]] = match.group(2).strip()
    return values


def _parse_thermal_sensors(text: str, warnings: list[str]) -> list[ThermalSensor]:
    sensors: list[ThermalSensor] = []
    for line in text.splitlines():
        if "temperature" not in line.lower() and "sensor" not in line.lower():
            continue
        name = _inline_field(line, "name", "type|temperature|temp|severity|throttl(?:ing|ed)|hot thresholds?|cold thresholds?") or _inline_field(line, "sensor", "type|temperature|temp|severity|throttl(?:ing|ed)|hot thresholds?|cold thresholds?")
        type_value = _inline_field(line, "type", "temperature|temp|severity|throttl(?:ing|ed)|hot thresholds?|cold thresholds?")
        temperature = _float_match(line, r"(?i)(?:temperature|temp)\s*[:=]\s*(-?\d+(?:\.\d+)?)\s*(?:°?c|celsius)?")
        if not name and temperature is None:
            continue
        if temperature is None and "temperature" in line.lower():
            warnings.append("malformed thermal temperature")
        severity = _normalize_severity(_inline_field(line, "severity", "throttl(?:ing|ed)|hot thresholds?|cold thresholds?")) or "UNKNOWN"
        sensors.append(
            ThermalSensor(
                name=_bounded_text((name or type_value or "unknown").strip()) or "unknown",
                type=_normalize_thermal_type(type_value or name),
                temperature_c=temperature,
                severity=severity,
                throttling=_first_bool(line, r"(?i)throttl(?:ing|ed)\s*[:=]\s*(true|false|1|0)"),
                hot_thresholds_c=_float_tokens(_inline_field(line, "hot thresholds?", "cold thresholds?") or ""),
                cold_thresholds_c=_float_tokens(_inline_field(line, "cold thresholds?", "") or ""),
                source="thermalservice",
            )
        )
    return sorted(sensors, key=lambda item: (item.type, item.name))


def _parse_cooling_devices(text: str, warnings: list[str]) -> list[CoolingDevice]:
    devices: list[CoolingDevice] = []
    for line in text.splitlines():
        if "cooling" not in line.lower():
            continue
        name = _inline_field(line, "name", "type|current(?: value)?|max(?:imum)?(?: value)?") or _inline_field(line, "cooling device", "type|current(?: value)?|max(?:imum)?(?: value)?")
        current = _integer_match(line, r"(?i)(?:current(?: value)?)\s*[:=]\s*(-?\d+)")
        maximum = _integer_match(line, r"(?i)(?:max(?:imum)?(?: value)?)\s*[:=]\s*(-?\d+)")
        if not name and current is None and maximum is None:
            warnings.append("malformed cooling-device entry")
            continue
        devices.append(
            CoolingDevice(
                name=_bounded_text((name or "unknown").strip()) or "unknown",
                type=_bounded_text((_inline_field(line, "type", "current(?: value)?|max(?:imum)?(?: value)?") or "UNKNOWN").strip(), 80) or "UNKNOWN",
                current_value=current,
                max_value=maximum,
                source="thermalservice",
            )
        )
    return sorted(devices, key=lambda item: (item.type, item.name))


def _parse_df_mounts(text: str, warnings: list[str]) -> list[StorageMount]:
    mounts: list[StorageMount] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0].lower() == "filesystem":
            continue
        try:
            total, used, available = (int(parts[index]) for index in (1, 2, 3))
        except ValueError:
            warnings.append("malformed df capacity row")
            continue
        percent_match = re.fullmatch(r"(\d+)%", parts[4])
        mounts.append(
            StorageMount(
                source=_bounded_text(parts[0], 256),
                target=_bounded_text(" ".join(parts[5:]), 256) or "<unknown>",
                filesystem=None,
                read_only=None,
                options=(),
                total_kb=total,
                used_kb=used,
                available_kb=available,
                usage_percent=int(percent_match.group(1)) if percent_match else None,
                virtual=parts[0] in {"tmpfs", "proc", "sysfs"},
                bind=False,
                overlay=False,
                source_command="storage.df_k",
            )
        )
    return mounts


def _parse_mount_lines(text: str, source_command: str, warnings: list[str]) -> list[StorageMount]:
    mounts: list[StorageMount] = []
    pattern = re.compile(r"^\s*(\S+)\s+on\s+(.+?)\s+type\s+(\S+)\s+\(([^)]*)\)")
    proc_pattern = re.compile(r"^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)")
    for line in text.splitlines():
        match = pattern.match(line) or proc_pattern.match(line)
        if not match:
            continue
        source, target, filesystem, options_text = match.groups()
        options = tuple(sorted({_bounded_text(value, 96) or "" for value in options_text.split(",") if value}))[:_MAX_SYSTEM_SUMMARY]
        mounts.append(
            StorageMount(
                source=_bounded_text(source, 256),
                target=_bounded_text(target, 256) or "<unknown>",
                filesystem=_bounded_text(filesystem, 80),
                read_only=True if "ro" in options else False if "rw" in options else None,
                options=options,
                total_kb=None,
                used_kb=None,
                available_kb=None,
                usage_percent=None,
                virtual=filesystem in {"tmpfs", "proc", "sysfs", "cgroup", "cgroup2", "binder"},
                bind="bind" in options,
                overlay=filesystem == "overlay",
                source_command=source_command,
            )
        )
    if text.strip() and not mounts and (" on " in text or "/" in text):
        warnings.append("no mount rows parsed")
    return mounts


def _merge_mounts(*collections: list[StorageMount]) -> list[StorageMount]:
    merged: dict[str, StorageMount] = {}
    for collection in collections:
        for mount in collection:
            existing = merged.get(mount.target)
            if existing is None or (existing.filesystem is None and mount.filesystem is not None):
                if existing is not None:
                    mount = StorageMount(
                        source=mount.source or existing.source,
                        target=mount.target,
                        filesystem=mount.filesystem,
                        read_only=mount.read_only,
                        options=mount.options,
                        total_kb=existing.total_kb,
                        used_kb=existing.used_kb,
                        available_kb=existing.available_kb,
                        usage_percent=existing.usage_percent,
                        virtual=mount.virtual,
                        bind=mount.bind,
                        overlay=mount.overlay,
                        source_command=mount.source_command,
                    )
                merged[mount.target] = mount
    return sorted(merged.values(), key=lambda item: item.target)


def _parse_storage_volumes(text: str, warnings: list[str]) -> list[StorageVolume]:
    volumes: list[StorageVolume] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0].upper() not in _VOLUME_TYPES:
            continue
        volume_type = parts[0].upper()
        identifier = parts[1] if len(parts) > 1 else None
        state = next((part.upper() for part in parts if part.upper() in _VOLUME_STATES), "UNKNOWN")
        uuid = next((part for part in parts if re.fullmatch(r"[0-9a-fA-F-]{8,}", part)), None)
        disk = next((part for part in parts if part.startswith("disk:")), None)
        volumes.append(
            StorageVolume(
                id=_bounded_text(identifier, 128),
                type=volume_type,
                state=state,
                filesystem_uuid=_bounded_text(uuid, 128),
                disk_id=_bounded_text(disk, 128),
                primary="primary" in line.lower(),
                emulated=volume_type == "EMULATED",
                source="sm list-volumes all",
            )
        )
    if text.strip() and not volumes and "volume" in text.lower():
        warnings.append("no storage volumes parsed")
    return sorted(volumes, key=lambda item: (item.type, item.id or ""))


def _parse_filesystems(text: str) -> list[FilesystemSupport]:
    filesystems: list[FilesystemSupport] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        nodev = parts[0] == "nodev"
        name = parts[-1]
        if name:
            filesystems.append(FilesystemSupport(name=_bounded_text(name, 80) or "unknown", nodev=nodev))
    return sorted({item.name: item for item in filesystems}.values(), key=lambda item: item.name)


def _parse_partitions(text: str, warnings: list[str]) -> list[StoragePartition]:
    partitions: list[StoragePartition] = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$", line)
        if not match:
            continue
        partitions.append(
            StoragePartition(
                major=int(match.group(1)),
                minor=int(match.group(2)),
                blocks=int(match.group(3)),
                name=match.group(4),
            )
        )
    if text.strip() and "major" in text.lower() and not partitions:
        warnings.append("no partitions parsed")
    return sorted(partitions, key=lambda item: (item.major, item.minor, item.name))


def _normalize_audio_direction(value: str | None) -> str:
    upper = (value or "").upper()
    if "BIDIRECTION" in upper:
        return "BIDIRECTIONAL"
    if "INPUT" in upper or "_IN_" in upper:
        return "INPUT"
    if "OUTPUT" in upper or "_OUT_" in upper:
        return "OUTPUT"
    return "UNKNOWN"


def _normalize_audio_role(value: str | None) -> str:
    upper = (value or "").upper()
    if "SOURCE" in upper:
        return "SOURCE"
    if "SINK" in upper:
        return "SINK"
    return "UNKNOWN"


def _normalize_battery_status(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = re.sub(r"[^A-Z]", "_", value.upper()).strip("_")
    aliases = {"NOTCHARGING": "NOT_CHARGING", "NOT_CHARGING": "NOT_CHARGING", "5": "FULL", "4": "NOT_CHARGING", "3": "DISCHARGING", "2": "CHARGING", "1": "UNKNOWN"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in _BATTERY_STATUS_VALUES else "UNKNOWN"


def _normalize_battery_health(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = re.sub(r"[^A-Z]", "_", value.upper()).strip("_")
    aliases = {"OVER_VOLTAGE": "OVER_VOLTAGE", "UNSPECIFIED_FAILURE": "UNSPECIFIED_FAILURE", "1": "UNKNOWN", "2": "GOOD", "3": "OVERHEAT", "4": "DEAD", "5": "OVER_VOLTAGE", "6": "UNSPECIFIED_FAILURE", "7": "COLD"}
    return aliases.get(normalized, normalized if normalized in _BATTERY_HEALTH_VALUES else "UNKNOWN")


def _normalize_plugged(value: str | None, values: Mapping[str, str]) -> str | None:
    flags = [name for name in ("ac", "usb", "wireless", "dock") if _bool_value(values.get(f"{name} powered"))]
    if flags:
        return "MULTIPLE" if len(flags) > 1 else flags[0].upper()
    if value is None:
        return None
    normalized = value.upper().replace(" ", "_")
    if normalized.isdigit():
        code = int(normalized)
        mapping = {0: "NONE", 1: "AC", 2: "USB", 4: "WIRELESS", 8: "DOCK"}
        if code in mapping:
            return mapping[code]
        return "MULTIPLE" if code > 0 and code & (code - 1) else "UNKNOWN"
    matches = [name for name in ("AC", "USB", "WIRELESS", "DOCK") if name in normalized]
    if not matches:
        return "NONE" if "NONE" in normalized or "UNPLUGGED" in normalized else "UNKNOWN"
    return matches[0] if len(matches) == 1 else "MULTIPLE"


def _normalize_thermal_type(value: str | None) -> str:
    upper = (value or "").upper().replace("-", "_").replace(" ", "_")
    aliases = {"USB": "USB_PORT", "PA": "POWER_AMPLIFIER", "BCLVOLTAGE": "BCL_VOLTAGE", "BCLCURRENT": "BCL_CURRENT", "BCLPERCENTAGE": "BCL_PERCENTAGE"}
    normalized = aliases.get(upper.replace("_", ""), upper)
    return normalized if normalized in _THERMAL_SENSOR_TYPES else "UNKNOWN"


def _normalize_severity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = re.sub(r"[^A-Z]", "_", value.upper()).strip("_")
    return normalized if normalized in _THERMAL_SEVERITIES else "UNKNOWN"


def _normalize_wakefulness(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = re.sub(r"[^A-Z]", "_", value.upper()).strip("_")
    return normalized if normalized in _WAKEFULNESS_VALUES else "UNKNOWN"


def _labeled_status(text: str, label: str) -> str | None:
    value = _first_match(text, rf"(?im)^\s*{label}\s*(?:status)?\s*[:=]\s*([^\r\n]+)")
    if value is None:
        return None
    return "unavailable" if any(token in value.lower() for token in ("unavailable", "not found", "denied")) else "available"


def _service_status(text: str, keyword: str) -> str | None:
    if not text.strip():
        return None
    lower = text.lower()
    if any(marker in lower for marker in ("permission denied", "permission denial", "not found", "can't find service", "unknown command")):
        return "unavailable"
    return "available" if keyword.lower() in lower else "unknown"


def _count_or_labeled(text: str, label: str) -> int | None:
    return _integer_match(text, rf"(?im)^\s*(?:{label})\s*[:=]\s*(\d+)")


def _token_values(text: str, label: str) -> tuple[str, ...]:
    value = _first_match(text, rf"(?im)^\s*{label}\s*[:=]\s*([^\r\n]+)")
    if value is None:
        return ()
    return tuple(sorted({_bounded_text(token.strip(), 96) or "" for token in re.split(r"[,| ]+", value) if token.strip()}))[:_MAX_SYSTEM_SUMMARY]


def _integer_tokens(values: tuple[str, ...]) -> tuple[int, ...]:
    return tuple(sorted({int(value) for value in values if value.isdigit()}))


def _integer_value(value: str | None) -> int | None:
    return int(value) if value and re.fullmatch(r"-?\d+", value.strip()) else None


def _unit_integer(value: str | None, units: tuple[str, ...], warnings: list[str], field: str) -> int | None:
    if value is None:
        return None
    match = re.fullmatch(r"\s*(-?\d+)\s*([A-Za-zµ_-]+)?\s*", value)
    if not match:
        warnings.append(f"malformed {field}")
        return None
    unit = (match.group(2) or "").lower().replace("µ", "u")
    if unit not in units:
        warnings.append(f"unknown units for {field}")
        return None
    return int(match.group(1))


def _temperature_tenths(value: str | None, warnings: list[str]) -> int | None:
    if value is None:
        return None
    match = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*(tenths?(?:\s*of\s*(?:a\s*)?degree)?\s*c|deci(?:celsius)?|°?c)?\s*", value, re.IGNORECASE)
    if not match:
        warnings.append("malformed temperature")
        return None
    unit = (match.group(2) or "").lower()
    if not unit:
        warnings.append("unknown units for temperature")
        return None
    number = float(match.group(1))
    if "tenths" in unit or "deci" in unit:
        return round(number)
    return round(number * 10)


def _bool_value(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    return None


def _integer_match(text: str, pattern: str) -> int | None:
    match = re.search(pattern, text)
    return int(match.group(1)) if match else None


def _float_match(text: str, pattern: str) -> float | None:
    match = re.search(pattern, text)
    return float(match.group(1)) if match else None


def _float_tokens(text: str) -> tuple[float, ...]:
    return tuple(sorted({float(value) for value in re.findall(r"-?\d+(?:\.\d+)?", text)}))[:_MAX_SYSTEM_SUMMARY]


def _primary_uuid_state(text: str) -> str | None:
    value = text.strip()
    if not value:
        return None
    if value.lower() in {"null", "none", "primary_physical"}:
        return value.lower()
    return "present"


def _storage_disk_count(text: str) -> int | None:
    if not text.strip():
        return None
    labeled = _count_or_labeled(text, "disks")
    if labeled is not None:
        return labeled
    lines = [line for line in text.splitlines() if line.strip() and not line.lower().startswith("error")]
    return len(lines) or None


def _first_storage_property(properties: Mapping[str, str], names: tuple[str, ...]) -> str | None:
    return next((properties[name] for name in names if properties.get(name)), None)


def _inline_field(text: str, label: str, following_labels: str) -> str | None:
    lookahead = rf"(?=\s+(?:{following_labels})\s*[:=]|$)" if following_labels else r"$"
    match = re.search(rf"(?i){label}\s*[:=]\s*(.*?){lookahead}", text)
    return match.group(1).strip() if match else None


def _bounded_text(value: str | None, limit: int = 160) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."


def _bounded_warnings(warnings: list[str]) -> tuple[str, ...]:
    unique = list(dict.fromkeys(warnings))
    if len(unique) > _MAX_SYSTEM_SUMMARY:
        unique = unique[: _MAX_SYSTEM_SUMMARY - 1] + ["additional parse warnings truncated"]
    return tuple(unique)


_TRANSPORT_VALUES = {
    "CELLULAR",
    "WIFI",
    "BLUETOOTH",
    "ETHERNET",
    "VPN",
    "WIFI_AWARE",
    "LOWPAN",
    "USB",
}
_INTERFACE_LINE_PATTERN = re.compile(
    r"(?m)^\s*\d+:\s+([A-Za-z0-9._@-]+):\s+<([^>]*)>(.*)$"
)
_INPUT_CLASS_ALIASES = {
    "TOUCH": "TOUCHSCREEN",
    "TOUCH_MT": "TOUCHSCREEN",
    "TOUCHSCREEN": "TOUCHSCREEN",
    "KEYBOARD": "KEYBOARD",
    "ALPHAKEY": "KEYBOARD",
    "CURSOR": "MOUSE",
    "MOUSE": "MOUSE",
    "JOYSTICK": "GAMEPAD",
    "GAMEPAD": "GAMEPAD",
    "DPAD": "BUTTONS",
    "BUTTON": "BUTTONS",
    "BUTTONS": "BUTTONS",
    "ROTARY_ENCODER": "ROTARY_ENCODER",
    "SWITCH": "SWITCH",
    "VIBRATOR": "VIBRATOR",
}


def parse_network_info(
    connectivity_text: str,
    ip_link_text: str = "",
    wifi_status_text: str = "",
    airplane_text: str = "",
    bluetooth_text: str = "",
) -> NetworkInventory:
    """Parse bounded connectivity state without joining, scanning, or probing networks."""

    warnings: list[str] = []
    interfaces = _parse_network_interfaces(ip_link_text, warnings)
    transports = _parse_network_transports(connectivity_text)
    if connectivity_text.strip() and not transports and "transport" in connectivity_text.lower():
        warnings.append("no network transports parsed")
    if len(interfaces) > _MAX_SYSTEM_SUMMARY:
        warnings.append(f"network interface summary truncated to {_MAX_SYSTEM_SUMMARY} items")
    active_count = _count_or_labeled(connectivity_text, "(?:current )?(?:active )?networks?")
    if active_count is None:
        agent_count = len(re.findall(r"(?im)^\s*NetworkAgentInfo\b", connectivity_text))
        active_count = agent_count or None
    return NetworkInventory(
        connectivity_service_status=_service_status(connectivity_text, "connectivity"),
        active_network_count=active_count,
        transport_types=transports,
        interfaces=tuple(interfaces[:_MAX_SYSTEM_SUMMARY]),
        wifi_service_status=_service_status(wifi_status_text, "wifi"),
        wifi_enabled=_wifi_enabled(wifi_status_text),
        airplane_mode_enabled=_settings_bool(airplane_text),
        bluetooth_enabled=_settings_bool(bluetooth_text),
        parse_warnings=_bounded_warnings(warnings),
    )


def parse_graphics_info(
    surface_flinger_text: str,
    gpu_text: str = "",
    egl_property_text: str = "",
    vulkan_property_text: str = "",
) -> GraphicsInventory:
    """Parse GPU identification lines without rendering or benchmarking."""

    warnings: list[str] = []
    combined = "\n".join((surface_flinger_text, gpu_text))
    gles_vendor, gles_renderer, gles_version = _parse_gles_line(combined)
    if surface_flinger_text.strip() and gles_vendor is None and "gles" in surface_flinger_text.lower():
        warnings.append("no GLES identification line parsed")
    return GraphicsInventory(
        surface_flinger_status=_service_status(surface_flinger_text, "surfaceflinger"),
        gles_vendor=gles_vendor,
        gles_renderer=gles_renderer,
        gles_version=gles_version,
        egl_hardware=_property_value_text(egl_property_text),
        vulkan_hardware=_property_value_text(vulkan_property_text),
        vulkan_api_version=_bounded_text(
            _first_match(combined, r"(?im)^\s*vulkan(?:[ _-]?api)?[ _-]?version\s*[:=]\s*([^\r\n,]+)")
        ),
        parse_warnings=_bounded_warnings(warnings),
    )


def parse_input_info(input_text: str, devices_text: str = "") -> InputInventory:
    """Parse input-device identity without reading, sampling, or injecting events."""

    warnings: list[str] = []
    devices = _parse_dumpsys_input_devices(input_text, warnings)
    known_names = {device.name for device in devices}
    for device in _parse_proc_input_devices(devices_text, warnings):
        if device.name not in known_names:
            devices.append(device)
            known_names.add(device.name)
    if len(devices) > _MAX_SYSTEM_SUMMARY:
        warnings.append(f"input device summary truncated to {_MAX_SYSTEM_SUMMARY} items")
    bounded = tuple(devices[:_MAX_SYSTEM_SUMMARY])
    return InputInventory(
        input_service_status=_service_status(input_text, "input"),
        device_count=len(bounded),
        devices=bounded,
        keyboard_count=sum(1 for device in bounded if "KEYBOARD" in device.classes),
        touchscreen_count=sum(1 for device in bounded if "TOUCHSCREEN" in device.classes),
        parse_warnings=_bounded_warnings(warnings),
    )


def parse_memory_info(
    meminfo_text: str,
    swaps_text: str = "",
    low_ram_property_text: str = "",
) -> MemoryInventory:
    """Parse memory and swap totals only when /proc labels declare kB units."""

    warnings: list[str] = []
    total_kb = _meminfo_kb(meminfo_text, "MemTotal", warnings)
    free_kb = _meminfo_kb(meminfo_text, "MemFree", warnings)
    available_kb = _meminfo_kb(meminfo_text, "MemAvailable", warnings)
    swap_total_kb = _meminfo_kb(meminfo_text, "SwapTotal", warnings)
    swap_free_kb = _meminfo_kb(meminfo_text, "SwapFree", warnings)
    if meminfo_text.strip() and total_kb is None and "memtotal" not in meminfo_text.lower():
        warnings.append("no meminfo values parsed")
    swap_device_count, zram_swap_present = _parse_swaps(swaps_text, warnings)
    return MemoryInventory(
        total_kb=total_kb,
        free_kb=free_kb,
        available_kb=available_kb,
        swap_total_kb=swap_total_kb,
        swap_free_kb=swap_free_kb,
        swap_device_count=swap_device_count,
        zram_swap_present=zram_swap_present,
        low_ram_device=_bool_value(_property_value_text(low_ram_property_text)),
        parse_warnings=_bounded_warnings(warnings),
    )


def _parse_network_interfaces(text: str, warnings: list[str]) -> list[NetworkInterface]:
    interfaces: list[NetworkInterface] = []
    seen: set[str] = set()
    for match in _INTERFACE_LINE_PATTERN.finditer(text):
        name = match.group(1).split("@", 1)[0]
        if not name or name in seen:
            continue
        seen.add(name)
        remainder = match.group(3)
        flags = tuple(sorted({token for token in match.group(2).split(",") if token}))
        state = _first_match(remainder, r"\bstate\s+([A-Z_-]+)")
        link_type = _first_match(text, rf"(?ms){re.escape(match.group(0))}\s*\n\s*link/([A-Za-z0-9_-]+)")
        interfaces.append(
            NetworkInterface(
                name=_bounded_text(name, 64) or "unknown",
                state=state,
                mtu=_integer_match(remainder, r"\bmtu\s+(\d+)"),
                flags=flags[:_MAX_SYSTEM_SUMMARY],
                link_type=_bounded_text(link_type, 32),
                source="network.ip_link",
            )
        )
    if text.strip() and not interfaces and "mtu" in text.lower():
        warnings.append("no network interfaces parsed")
    return sorted(interfaces, key=lambda item: _natural_sort_key(item.name))


def _parse_network_transports(text: str) -> tuple[str, ...]:
    values: list[str] = []
    for match in re.finditer(r"(?im)^\s*transports?\s*[:=]\s*([^\r\n]+)", text):
        for token in re.split(r"[,|&\s]+", match.group(1)):
            normalized = token.strip().upper()
            if not normalized:
                continue
            if normalized not in _TRANSPORT_VALUES:
                normalized = "UNKNOWN"
            if normalized not in values:
                values.append(normalized)
    return tuple(values[:_MAX_SYSTEM_SUMMARY])


def _wifi_enabled(text: str) -> bool | None:
    match = re.search(r"(?im)^\s*wifi\s+is\s+(enabled|disabled)\b", text)
    if match:
        return match.group(1).lower() == "enabled"
    return _first_bool(text, r"(?im)^\s*wifi\s*(?:enabled)?\s*[:=]\s*(true|false|1|0)")


def _settings_bool(text: str) -> bool | None:
    value = text.strip().splitlines()[0].strip() if text.strip() else ""
    if not value or value.lower() == "null":
        return None
    return _bool_value(value)


def _parse_gles_line(text: str) -> tuple[str | None, str | None, str | None]:
    match = re.search(r"(?im)^\s*GLES\s*[:=]\s*([^\r\n]+)", text)
    if not match:
        return None, None, None
    parts = [part.strip() for part in match.group(1).split(",", 2)]
    vendor = _bounded_text(parts[0]) if parts and parts[0] else None
    renderer = _bounded_text(parts[1]) if len(parts) > 1 and parts[1] else None
    version = _bounded_text(parts[2]) if len(parts) > 2 and parts[2] else None
    return vendor, renderer, version


def _property_value_text(text: str) -> str | None:
    value = text.strip().splitlines()[0].strip() if text.strip() else ""
    if not value or value.lower() in {"null", "undefined"}:
        return None
    if "not found" in value.lower() or "inaccessible" in value.lower():
        return None
    return _bounded_text(value, 96)


def _parse_dumpsys_input_devices(text: str, warnings: list[str]) -> list[InputDevice]:
    devices: list[InputDevice] = []
    blocks = re.split(r"(?im)^(?=\s*Device\s+-?\d+\s*:)", text)
    for block in blocks:
        header = re.match(r"(?im)^\s*Device\s+(-?\d+)\s*:\s*([^\r\n]+)", block)
        if not header:
            continue
        name = _bounded_text(header.group(2).strip(), 128)
        if not name:
            warnings.append("input device without a name skipped")
            continue
        identifier = _first_match(block, r"(?im)^\s*identifier\s*[:=]\s*([^\r\n]+)") or ""
        devices.append(
            InputDevice(
                id=header.group(1),
                name=name,
                vendor_id=_first_match(identifier, r"(?i)\bvendor\s*=\s*(0x[0-9a-f]+|\d+)"),
                product_id=_first_match(identifier, r"(?i)\bproduct\s*=\s*(0x[0-9a-f]+|\d+)"),
                bus=_first_match(identifier, r"(?i)\bbus\s*=\s*(0x[0-9a-f]+|\d+)"),
                classes=_normalize_input_classes(_first_match(block, r"(?im)^\s*classes\s*[:=]\s*([^\r\n]+)")),
                external=_first_bool(block, r"(?im)^\s*is?_?external\s*[:=]\s*(true|false|1|0)"),
                source="input.dumpsys",
            )
        )
    if text.strip() and not devices and re.search(r"(?im)^\s*Device\s+", text):
        warnings.append("no input devices parsed from dumpsys input")
    return devices


def _parse_proc_input_devices(text: str, warnings: list[str]) -> list[InputDevice]:
    devices: list[InputDevice] = []
    for block in re.split(r"\n\s*\n", text):
        if not block.strip():
            continue
        identity = re.search(
            r"(?im)^I:\s*Bus=([0-9a-f]+)\s+Vendor=([0-9a-f]+)\s+Product=([0-9a-f]+)",
            block,
        )
        name = _first_match(block, r"(?im)^N:\s*Name=\"([^\"\r\n]*)\"")
        if name is None:
            if identity is not None:
                warnings.append("input device block without a name skipped")
            continue
        handlers = _first_match(block, r"(?im)^H:\s*Handlers=([^\r\n]+)") or ""
        classes: list[str] = []
        if re.search(r"\bkbd\b", handlers):
            classes.append("KEYBOARD")
        if re.search(r"\bmouse\d*\b", handlers):
            classes.append("MOUSE")
        if re.search(r"(?im)^B:\s*ABS=", block):
            classes.append("TOUCHSCREEN")
        devices.append(
            InputDevice(
                id=None,
                name=_bounded_text(name, 128) or "unknown",
                vendor_id=identity.group(2).lower() if identity else None,
                product_id=identity.group(3).lower() if identity else None,
                bus=identity.group(1).lower() if identity else None,
                classes=tuple(sorted(set(classes))),
                external=None,
                source="input.proc_devices",
            )
        )
    return devices


def _normalize_input_classes(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    normalized: set[str] = set()
    for token in re.split(r"[,|\s]+", value):
        cleaned = re.sub(r"[^A-Z_]", "", token.upper())
        if not cleaned:
            continue
        normalized.add(_INPUT_CLASS_ALIASES.get(cleaned, "UNKNOWN"))
    return tuple(sorted(normalized))


def _meminfo_kb(text: str, label: str, warnings: list[str]) -> int | None:
    match = re.search(rf"(?im)^\s*{label}\s*:\s*([^\r\n]+)$", text)
    if not match:
        return None
    value = re.fullmatch(r"\s*(\d+)\s*kB\s*", match.group(1))
    if not value:
        warnings.append(f"malformed {label} value")
        return None
    return int(value.group(1))


def _parse_swaps(text: str, warnings: list[str]) -> tuple[int | None, bool | None]:
    if not text.strip():
        return None, None
    if re.search(r"(?i)no such file|permission denied|not found|inaccessible", text):
        return None, None
    entries: list[str] = []
    malformed = False
    for line in text.splitlines()[1:]:
        if not line.strip():
            continue
        columns = line.split()
        if len(columns) < 3 or not columns[0].startswith("/"):
            malformed = True
            continue
        entries.append(columns[0])
    if malformed:
        warnings.append("malformed swap table entries skipped")
    return len(entries), any("zram" in entry.lower() for entry in entries)
