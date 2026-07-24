"""Core immutable data models for device evidence and analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class CommandResult:
    """The complete observable result of one host-side ADB invocation."""

    command: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool


@dataclass(frozen=True)
class EvidenceCommand:
    """A named command result stored in an evidence bundle."""

    id: str
    section: str
    result: CommandResult
    status_override: str | None = None


@dataclass(frozen=True)
class DeviceInfo:
    """A target reported by `adb devices -l`."""

    serial: str
    state: str
    details: tuple[str, ...]


@dataclass(frozen=True)
class CpuCluster:
    """A normalized native CPU implementer/part cluster."""

    implementer: str
    part: str
    count: int


@dataclass(frozen=True)
class CpuTopology:
    """The observable online CPU count and normalized cluster composition."""

    online_cpu_count: int | None
    clusters: tuple[CpuCluster, ...]


@dataclass(frozen=True)
class DisplayMode:
    """A display mode observed in a dumpsys display response."""

    mode_id: str | None
    width: int | None
    height: int | None
    refresh_rate: float | None


@dataclass(frozen=True)
class DisplayInfo:
    """Observable display geometry, density, modes, and capabilities."""

    physical_size: str | None
    override_size: str | None
    physical_density: int | None
    override_density: int | None
    logical_width: int | None
    logical_height: int | None
    refresh_rates: tuple[float, ...]
    active_mode: str | None
    supported_modes: tuple[DisplayMode, ...]
    hdr_types: tuple[str, ...]
    wide_color_support: bool | None
    display_count: int | None


@dataclass(frozen=True)
class TelephonyInfo:
    """Observable telephony and radio inventory with identifiers excluded."""

    phone_count: int | None
    sim_states: tuple[str, ...]
    network_types: tuple[str, ...]
    operator_alpha: tuple[str, ...]
    operator_numeric: tuple[str, ...]
    operator_country_iso: tuple[str, ...]
    roaming: tuple[bool, ...]
    subscription_count: int | None
    baseband: str | None
    ril_implementation: str | None
    radio_properties: Mapping[str, str]


@dataclass(frozen=True)
class PackageInfo:
    """Small, stable package metadata summary; raw dumps remain in the bundle."""

    package_name: str
    installed: bool | None
    version_name: str | None
    version_code: int | None
    min_sdk: int | None
    target_sdk: int | None
    first_install_time: str | None
    last_update_time: str | None
    installer_package_name: str | None
    code_paths: tuple[str, ...]
    enabled: bool | None
    stopped: bool | None
    suspended: bool | None
    system_app: bool | None
    privileged_app: bool | None
    debuggable: bool | None
    signing_certificate_digests: tuple[str, ...]


@dataclass(frozen=True)
class MagiskInfo:
    """Read-only root and Magisk inventory."""

    root_available: bool
    root_uid: int | None
    root_context: str | None
    magisk_installed: bool | None
    magisk_version: str | None
    magisk_version_code: int | None
    magisk_path: str | None
    zygisk_setting: str | None
    denylist_setting: str | None
    module_names: tuple[str, ...]
    cloud_magisk_property: str | None


@dataclass(frozen=True)
class RuntimeMarkers:
    """Environment-specific markers kept informational by design."""

    markers: tuple[str, ...]
    mount_points: tuple[str, ...]
    process_names: tuple[str, ...]
    service_names: tuple[str, ...]


@dataclass(frozen=True)
class KernelInfo:
    """Observable kernel release metadata."""

    release: str | None
    lineage: str | None
    architecture: str | None = None


@dataclass(frozen=True)
class PackageExpectation:
    """Explicit profile expectations for one package."""

    required: bool
    allowed_version_code_ranges: tuple[tuple[int, int], ...]
    required_enabled: bool | None
    required_not_suspended: bool | None


@dataclass(frozen=True)
class ExpectedProfile:
    """An explicit reference profile used to evaluate observed device data."""

    schema_version: str
    name: str
    identity: Mapping[str, str]
    build: Mapping[str, str]
    kernel_allowed_lineages: tuple[str, ...]
    allowed_cpu_topologies: tuple[CpuTopology, ...]
    display_allowed_physical_sizes: tuple[str, ...] = ()
    display_allowed_density_ranges: tuple[tuple[int, int], ...] = ()
    display_allowed_refresh_rates: tuple[float, ...] = ()
    telephony_allowed_operator_numeric: tuple[str, ...] = ()
    telephony_allowed_country_iso: tuple[str, ...] = ()
    telephony_allowed_network_types: tuple[str, ...] = ()
    telephony_allowed_ril_vendors: tuple[str, ...] = ()
    telephony_allowed_baseband_patterns: tuple[str, ...] = ()
    package_expectations: Mapping[str, PackageExpectation] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    """A neutral, evidence-backed profile comparison result."""

    id: str
    title: str
    category: str
    severity: str
    confidence: str
    summary: str
    evidence: tuple[str, ...]
    expected: str | None
    observed: str | None
    recommendation: str | None = None


@dataclass(frozen=True)
class Comparison:
    """The explicit state of one profile-backed comparison."""

    field: str
    category: str
    status: str
    expected: str | None
    observed: str | None
    evidence: tuple[str, ...]
