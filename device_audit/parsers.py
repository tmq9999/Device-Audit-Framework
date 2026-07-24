"""Defensive parsers for Phase 1 Android device evidence."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import re

from device_audit.models import (
    CpuCluster,
    CpuTopology,
    DisplayInfo,
    DisplayMode,
    KernelInfo,
    MagiskInfo,
    PackageInfo,
    RuntimeMarkers,
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
