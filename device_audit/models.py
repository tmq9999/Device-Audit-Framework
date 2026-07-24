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
class CameraDevice:
    """Bounded normalized summary for one observable camera device."""

    id: str
    facing: str
    orientation: int | None
    hardware_level: str
    physical_ids: tuple[str, ...]
    flash_available: bool | None
    capability_names: tuple[str, ...]
    output_format_count: int
    representative_output_sizes: tuple[str, ...]
    fps_ranges: tuple[tuple[int, int], ...]
    provider_name: str | None = None
    device_version: str | None = None

@dataclass(frozen=True)
class CameraInventory:
    """Read-only camera-service inventory with deterministic bounds."""

    camera_count: int
    logical_camera_count: int
    physical_camera_count: int
    cameras: tuple[CameraDevice, ...]
    concurrent_combinations: tuple[tuple[str, ...], ...]
    active_client_count: int | None
    service_status: str | None
    provider_names: tuple[str, ...]
    device_versions: tuple[str, ...]
    parse_warnings: tuple[str, ...]

@dataclass(frozen=True)
class SensorDevice:
    """Bounded normalized summary for one sensorservice entry."""

    handle: str
    name: str
    vendor: str | None
    version: int | None
    type_value: int | None
    string_type: str | None
    normalized_type: str
    reporting_mode: str | None
    wake_up: bool | None
    dynamic: bool | None
    maximum_range: float | None
    resolution: float | None
    power: float | None
    minimum_delay: int | None
    maximum_delay: int | None
    fifo_reserved_count: int | None
    fifo_maximum_count: int | None
    required_permission: str | None

@dataclass(frozen=True)
class SensorInventory:
    """Read-only sensorservice inventory without collecting sensor samples."""

    sensor_count: int
    sensors: tuple[SensorDevice, ...]
    type_counts: Mapping[str, int]
    vendor_counts: Mapping[str, int]
    wakeup_sensor_count: int
    dynamic_sensor_count: int
    active_sensor_count: int | None
    active_connection_count: int | None
    service_status: str | None
    parse_warnings: tuple[str, ...]

@dataclass(frozen=True)
class HalInterface:
    """One normalized HIDL, AIDL, binder, or passthrough interface."""

    family: str
    full_interface: str
    version: str | None
    instance: str | None
    transport: str
    architecture: str | None
    service_state: str | None
    source: str
    server_pid: int | None = None
    client_pids: tuple[int, ...] = ()
    thread_usage: str | None = None

@dataclass(frozen=True)
class HalInventory:
    """Bounded HAL and native-service inventory."""

    hal_count: int
    hidl_count: int
    aidl_count: int
    passthrough_count: int
    binderized_count: int
    lazy_count: int
    families: tuple[str, ...]
    interfaces: tuple[HalInterface, ...]
    binder_service_count: int
    dumpsys_service_count: int
    hal_properties: Mapping[str, str]
    parse_warnings: tuple[str, ...]


@dataclass(frozen=True)
class AudioDevice:
    """A bounded, metadata-only audio device or port observation."""

    id: str
    role: str
    direction: str
    device_type: str | None
    address: str | None
    product_name: str | None
    connected: bool | None
    active: bool | None
    formats: tuple[str, ...]
    sample_rates: tuple[int, ...]
    channel_masks: tuple[str, ...]
    flags: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class AudioInventory:
    """Read-only audio service and route metadata without media activity."""

    service_status: str | None
    audio_server_status: str | None
    audio_policy_status: str | None
    current_mode: str | None
    master_muted: bool | None
    microphone_muted: bool | None
    fixed_volume: bool | None
    communication_device: str | None
    output_devices: tuple[AudioDevice, ...]
    input_devices: tuple[AudioDevice, ...]
    output_thread_count: int | None
    input_thread_count: int | None
    active_playback_client_count: int | None
    active_recording_client_count: int | None
    audio_focus_owner_count: int | None
    active_patch_count: int | None
    effect_count: int | None
    parse_warnings: tuple[str, ...]


@dataclass(frozen=True)
class BatteryInventory:
    """Observable battery and charging state without health inference."""

    battery_present: bool | None
    battery_status: str | None
    battery_health: str | None
    plugged_source: str | None
    charging: bool | None
    level_percent: int | None
    scale: int | None
    voltage_mv: int | None
    temperature_tenths_c: int | None
    temperature_c: float | None
    current_now_ua: int | None
    current_average_ua: int | None
    charge_counter_uah: int | None
    energy_counter_nwh: int | None
    max_charging_current_ua: int | None
    max_charging_voltage_uv: int | None
    technology: str | None
    property_service_status: str | None
    parse_warnings: tuple[str, ...]


@dataclass(frozen=True)
class ThermalSensor:
    """One normalized thermal sensor observation."""

    name: str
    type: str
    temperature_c: float | None
    severity: str
    throttling: bool | None
    hot_thresholds_c: tuple[float, ...]
    cold_thresholds_c: tuple[float, ...]
    source: str


@dataclass(frozen=True)
class CoolingDevice:
    """One observable cooling-device state."""

    name: str
    type: str
    current_value: int | None
    max_value: int | None
    source: str


@dataclass(frozen=True)
class ThermalInventory:
    """Read-only thermal and power state inventory."""

    thermal_service_status: str | None
    thermal_hal_status: str | None
    current_thermal_severity: str | None
    temperature_sensors: tuple[ThermalSensor, ...]
    cooling_devices: tuple[CoolingDevice, ...]
    power_service_status: str | None
    wakefulness: str | None
    interactive: bool | None
    battery_saver_enabled: bool | None
    adaptive_power_saver_enabled: bool | None
    fixed_performance_mode_enabled: bool | None
    current_power_mode: str | None
    device_idle_mode: bool | None
    light_idle_mode: bool | None
    active_wake_lock_count: int | None
    suspend_blocker_count: int | None
    last_wake_reason: str | None
    last_sleep_reason: str | None
    parse_warnings: tuple[str, ...]


@dataclass(frozen=True)
class StorageMount:
    """A normalized mount observation with optional capacity metrics."""

    source: str | None
    target: str
    filesystem: str | None
    read_only: bool | None
    options: tuple[str, ...]
    total_kb: int | None
    used_kb: int | None
    available_kb: int | None
    usage_percent: int | None
    virtual: bool
    bind: bool
    overlay: bool
    source_command: str


@dataclass(frozen=True)
class StorageVolume:
    """An Android storage volume with identifiers redacted by report rendering."""

    id: str | None
    type: str
    state: str
    filesystem_uuid: str | None
    disk_id: str | None
    primary: bool | None
    emulated: bool | None
    source: str


@dataclass(frozen=True)
class StoragePartition:
    """One parsed /proc/partitions entry."""

    major: int
    minor: int
    blocks: int
    name: str


@dataclass(frozen=True)
class FilesystemSupport:
    """One filesystem name advertised by /proc/filesystems."""

    name: str
    nodev: bool


@dataclass(frozen=True)
class StorageInventory:
    """Read-only mount, volume, partition, and filesystem inventory."""

    mounts: tuple[StorageMount, ...]
    volumes: tuple[StorageVolume, ...]
    disk_count: int | None
    partitions: tuple[StoragePartition, ...]
    supported_filesystems: tuple[FilesystemSupport, ...]
    primary_storage_uuid_state: str | None
    mount_service_status: str | None
    encryption_state: str | None
    metadata_encryption_state: str | None
    parse_warnings: tuple[str, ...]


@dataclass(frozen=True)
class NetworkInterface:
    """One bounded network-interface observation without addresses."""

    name: str
    state: str | None
    mtu: int | None
    flags: tuple[str, ...]
    link_type: str | None
    source: str


@dataclass(frozen=True)
class NetworkInventory:
    """Read-only connectivity inventory with identifiers redacted before persistence."""

    connectivity_service_status: str | None
    active_network_count: int | None
    transport_types: tuple[str, ...]
    interfaces: tuple[NetworkInterface, ...]
    wifi_service_status: str | None
    wifi_enabled: bool | None
    airplane_mode_enabled: bool | None
    bluetooth_enabled: bool | None
    parse_warnings: tuple[str, ...]


@dataclass(frozen=True)
class GraphicsInventory:
    """Observable GPU and rendering inventory without running graphics work."""

    surface_flinger_status: str | None
    gles_vendor: str | None
    gles_renderer: str | None
    gles_version: str | None
    egl_hardware: str | None
    vulkan_hardware: str | None
    vulkan_api_version: str | None
    parse_warnings: tuple[str, ...]


@dataclass(frozen=True)
class InputDevice:
    """One normalized input-device observation."""

    id: str | None
    name: str
    vendor_id: str | None
    product_id: str | None
    bus: str | None
    classes: tuple[str, ...]
    external: bool | None
    source: str


@dataclass(frozen=True)
class InputInventory:
    """Read-only input-device inventory without injecting or sampling events."""

    input_service_status: str | None
    device_count: int
    devices: tuple[InputDevice, ...]
    keyboard_count: int
    touchscreen_count: int
    parse_warnings: tuple[str, ...]


@dataclass(frozen=True)
class MemoryInventory:
    """Observable memory and swap totals without benchmarks or pressure tests."""

    total_kb: int | None
    free_kb: int | None
    available_kb: int | None
    swap_total_kb: int | None
    swap_free_kb: int | None
    swap_device_count: int | None
    zram_swap_present: bool | None
    low_ram_device: bool | None
    parse_warnings: tuple[str, ...]


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
    camera_minimum_count: int | None = None
    camera_required_facing: tuple[str, ...] = ()
    camera_required_ids: tuple[str, ...] = ()
    camera_allowed_hardware_levels: tuple[str, ...] = ()
    camera_required_capabilities: tuple[str, ...] = ()
    sensors_minimum_count: int | None = None
    sensors_required_types: tuple[str, ...] = ()
    sensors_allowed_vendors: tuple[str, ...] = ()
    hal_required_interfaces: tuple[str, ...] = ()
    hal_required_families: tuple[str, ...] = ()
    hal_allowed_transports: tuple[str, ...] = ()
    audio_minimum_output_device_count: int | None = None
    audio_minimum_input_device_count: int | None = None
    audio_required_output_device_types: tuple[str, ...] = ()
    audio_required_input_device_types: tuple[str, ...] = ()
    audio_required_output_formats: tuple[str, ...] = ()
    audio_required_sample_rates: tuple[int, ...] = ()
    audio_require_service_available: bool | None = None
    audio_require_policy_available: bool | None = None
    battery_require_present: bool | None = None
    battery_allowed_health: tuple[str, ...] = ()
    battery_allowed_plugged_sources: tuple[str, ...] = ()
    battery_minimum_level_percent: int | None = None
    battery_maximum_temperature_tenths_c: int | None = None
    battery_require_property_service_available: bool | None = None
    thermal_require_service_available: bool | None = None
    thermal_required_sensor_types: tuple[str, ...] = ()
    thermal_allowed_current_severity: tuple[str, ...] = ()
    thermal_maximum_sensor_temperature_c: Mapping[str, float] = field(default_factory=dict)
    thermal_require_power_service_available: bool | None = None
    thermal_allowed_wakefulness: tuple[str, ...] = ()
    storage_required_filesystem_types: tuple[str, ...] = ()
    storage_required_mount_points: tuple[str, ...] = ()
    storage_require_data_mount_read_write: bool | None = None
    storage_minimum_data_available_kb: int | None = None
    storage_allowed_volume_types: tuple[str, ...] = ()
    storage_require_mount_service_available: bool | None = None
    network_required_interfaces: tuple[str, ...] = ()
    network_allowed_transport_types: tuple[str, ...] = ()
    network_require_connectivity_service_available: bool | None = None
    graphics_allowed_gles_vendors: tuple[str, ...] = ()
    graphics_allowed_gles_renderer_patterns: tuple[str, ...] = ()
    graphics_require_surface_flinger_available: bool | None = None
    input_minimum_device_count: int | None = None
    input_required_device_classes: tuple[str, ...] = ()
    memory_minimum_total_kb: int | None = None
    memory_maximum_total_kb: int | None = None
    memory_require_low_ram_flag: bool | None = None


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
