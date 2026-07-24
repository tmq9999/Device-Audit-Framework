"""Defensive parsers for Phase 1 Android device evidence."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
import re

from device_audit.models import (
    CpuCluster,
    CpuTopology,
    CameraDevice,
    CameraInventory,
    DisplayInfo,
    DisplayMode,
    HalInterface,
    HalInventory,
    KernelInfo,
    MagiskInfo,
    PackageInfo,
    RuntimeMarkers,
    SensorDevice,
    SensorInventory,
    TelephonyInfo,
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
    return match.group(1).lower() == "true" if match else None

def _natural_sort_key(value: str) -> tuple[object, ...]:
    return tuple(int(part) if part.isdigit() else part for part in re.split(r"(\d+)", value))
