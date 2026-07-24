from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from device_audit.analysis import analyze_bundle
from device_audit.bundle import BundleIntegrityError, load_evidence_bundle, write_evidence_bundle
from device_audit.capture import CaptureOptions
from device_audit.collectors import GRAPHICS_COMMANDS, INPUT_COMMANDS, MEMORY_COMMANDS, NETWORK_COMMANDS
from device_audit.models import CommandResult, EvidenceCommand
from device_audit.parsers import (
    parse_graphics_info,
    parse_input_info,
    parse_memory_info,
    parse_network_info,
)
from device_audit.profiles import ProfileValidationError, profile_from_mapping
from device_audit.redaction import redact_text
from device_audit.rules import compare_profile, evaluate_profile


FIXTURES = Path(__file__).parent / "fixtures"
PHASE5_FAMILIES = (
    "pixel_phase5",
    "samsung_phase5",
    "vmos_phase5",
    "aosp_emulator_phase5",
    "lineage_phase5",
    "malformed_phase5",
    "permission_denied_phase5",
    "unsupported_commands_phase5",
)
PHASE5_ARTIFACTS = (
    "network_connectivity.txt",
    "network_ip_link.txt",
    "network_wifi_status.txt",
    "network_airplane_mode.txt",
    "network_bluetooth_state.txt",
    "graphics_surface_flinger.txt",
    "graphics_gpu.txt",
    "graphics_egl_property.txt",
    "graphics_vulkan_property.txt",
    "input_dumpsys.txt",
    "input_proc_devices.txt",
    "memory_proc_meminfo.txt",
    "memory_proc_swaps.txt",
    "memory_low_ram_property.txt",
)


def fixture(family: str, name: str) -> str:
    return (FIXTURES / family / name).read_text(encoding="utf-8")


def phase5_network(family: str = "pixel_phase5"):
    return parse_network_info(
        fixture(family, "network_connectivity.txt"),
        fixture(family, "network_ip_link.txt"),
        fixture(family, "network_wifi_status.txt"),
        fixture(family, "network_airplane_mode.txt"),
        fixture(family, "network_bluetooth_state.txt"),
    )


def phase5_graphics(family: str = "pixel_phase5"):
    return parse_graphics_info(
        fixture(family, "graphics_surface_flinger.txt"),
        fixture(family, "graphics_gpu.txt"),
        fixture(family, "graphics_egl_property.txt"),
        fixture(family, "graphics_vulkan_property.txt"),
    )


def phase5_input(family: str = "pixel_phase5"):
    return parse_input_info(
        fixture(family, "input_dumpsys.txt"),
        fixture(family, "input_proc_devices.txt"),
    )


def phase5_memory(family: str = "pixel_phase5"):
    return parse_memory_info(
        fixture(family, "memory_proc_meminfo.txt"),
        fixture(family, "memory_proc_swaps.txt"),
        fixture(family, "memory_low_ram_property.txt"),
    )


def profile(**sections: object):
    return profile_from_mapping({"schema_version": "5.0", "name": "Synthetic Phase 5", **sections})


def test_phase5_fixture_families_declare_every_collector_artifact() -> None:
    for family in PHASE5_FAMILIES:
        assert {path.name for path in (FIXTURES / family).iterdir()} == set(PHASE5_ARTIFACTS)


def test_network_parser_normalizes_transports_interfaces_settings_and_crlf() -> None:
    network = phase5_network()
    crlf = parse_network_info(
        fixture("pixel_phase5", "network_connectivity.txt").replace("\n", "\r\n"),
        fixture("pixel_phase5", "network_ip_link.txt").replace("\n", "\r\n"),
    )

    assert network.transport_types == ("WIFI", "CELLULAR")
    assert network.active_network_count == 2
    assert [interface.name for interface in network.interfaces] == ["lo", "rmnet_data0", "wlan0"]
    wlan = next(interface for interface in network.interfaces if interface.name == "wlan0")
    assert wlan.state == "UP" and wlan.mtu == 1500 and wlan.link_type == "ether"
    assert network.wifi_enabled is True
    assert network.airplane_mode_enabled is False
    assert network.bluetooth_enabled is True
    assert crlf.transport_types == ("WIFI", "CELLULAR")
    assert crlf.interfaces


def test_network_parser_keeps_unknown_and_unsupported_data_inventory_only() -> None:
    malformed = phase5_network("malformed_phase5")
    denied = phase5_network("permission_denied_phase5")
    unsupported = phase5_network("unsupported_commands_phase5")

    assert not malformed.interfaces
    assert malformed.parse_warnings
    assert malformed.transport_types == ("UNKNOWN",)
    assert malformed.airplane_mode_enabled is None
    assert denied.connectivity_service_status == "unavailable"
    assert denied.wifi_service_status == "unavailable"
    assert unsupported.connectivity_service_status == "unavailable"
    assert unsupported.bluetooth_enabled is None


def test_graphics_parser_normalizes_gles_identity_without_guessing() -> None:
    graphics = phase5_graphics()
    emulator = phase5_graphics("aosp_emulator_phase5")
    malformed = phase5_graphics("malformed_phase5")

    assert graphics.gles_vendor == "ARM"
    assert graphics.gles_renderer == "Mali-G715-Immortalis MC11"
    assert graphics.gles_version == "OpenGL ES 3.2 v1.r44p1-01eac0"
    assert graphics.egl_hardware == "mali"
    assert graphics.vulkan_api_version == "1.3.264"
    assert emulator.gles_vendor == "Google (NVIDIA Corporation)"
    assert emulator.egl_hardware == "emulation"
    assert malformed.gles_vendor is None
    assert malformed.vulkan_hardware is None
    assert malformed.parse_warnings


def test_input_parser_merges_dumpsys_and_proc_sources_with_unicode() -> None:
    devices = phase5_input()
    lineage = phase5_input("lineage_phase5")
    malformed = phase5_input("malformed_phase5")

    assert devices.device_count == 2
    assert devices.keyboard_count == 1
    assert devices.touchscreen_count == 1
    touchscreen = next(device for device in devices.devices if "TOUCHSCREEN" in device.classes)
    assert touchscreen.vendor_id == "0x1234" and touchscreen.product_id == "0x5678"
    assert touchscreen.external is False
    assert lineage.devices[0].name == "Cảm ứng tổng hợp"
    assert not malformed.devices
    assert malformed.parse_warnings


def test_memory_parser_requires_kb_units_and_reads_swap_table() -> None:
    memory = phase5_memory()
    vmos = phase5_memory("vmos_phase5")
    malformed = phase5_memory("malformed_phase5")

    assert memory.total_kb == 12197892
    assert memory.available_kb == 5643212
    assert memory.swap_total_kb == 4194300
    assert memory.swap_device_count == 1
    assert memory.zram_swap_present is True
    assert memory.low_ram_device is False
    assert vmos.swap_device_count == 0
    assert vmos.zram_swap_present is False
    assert malformed.total_kb is None
    assert any("malformed MemTotal" in warning for warning in malformed.parse_warnings)


def test_phase5_profile_sections_are_inventory_only_when_absent_or_empty() -> None:
    observations = (phase5_network(), phase5_graphics(), phase5_input(), phase5_memory())
    for selected_profile in (profile(), profile(network={}, graphics={}, input={}, memory={})):
        comparisons = compare_profile({}, None, None, selected_profile, network=observations[0], graphics=observations[1], input_devices=observations[2], memory=observations[3])
        assert not [comparison for comparison in comparisons if comparison.category in {"network", "graphics", "input", "memory"}]
        assert evaluate_profile({}, None, None, selected_profile, network=observations[0], graphics=observations[1], input_devices=observations[2], memory=observations[3]) == []


def test_phase5_profile_rules_are_explicit_deterministic_and_no_extra_inventory_mismatch() -> None:
    selected_profile = profile(
        network={
            "required_interfaces": ["wlan0"],
            "allowed_transport_types": ["WIFI", "CELLULAR"],
            "require_connectivity_service_available": True,
        },
        graphics={
            "allowed_gles_vendors": ["ARM"],
            "allowed_gles_renderer_patterns": [r"Mali-G7\d+"],
            "require_surface_flinger_available": True,
        },
        input={"minimum_device_count": 2, "required_device_classes": ["TOUCHSCREEN", "KEYBOARD"]},
        memory={"minimum_total_kb": 4194304, "maximum_total_kb": 16777216, "require_low_ram_flag": False},
    )
    comparisons = compare_profile({}, None, None, selected_profile, network=phase5_network(), graphics=phase5_graphics(), input_devices=phase5_input(), memory=phase5_memory())

    assert comparisons
    assert {item.status for item in comparisons if item.category in {"network", "graphics", "input", "memory"}} == {"matched"}
    assert evaluate_profile({}, None, None, selected_profile, network=phase5_network(), graphics=phase5_graphics(), input_devices=phase5_input(), memory=phase5_memory()) == []


def test_phase5_profile_mismatches_only_declared_expectations() -> None:
    selected_profile = profile(
        network={"required_interfaces": ["eth7"]},
        graphics={"allowed_gles_vendors": ["Qualcomm"]},
        input={"minimum_device_count": 9},
        memory={"maximum_total_kb": 1024},
    )
    findings = evaluate_profile({}, None, None, selected_profile, network=phase5_network(), graphics=phase5_graphics(), input_devices=phase5_input(), memory=phase5_memory())

    assert [finding.id for finding in findings] == [
        "NETWORK_PROFILE_MISMATCH",
        "GRAPHICS_PROFILE_MISMATCH",
        "INPUT_PROFILE_MISMATCH",
        "MEMORY_PROFILE_MISMATCH",
    ]


def test_permission_and_unsupported_observations_do_not_create_false_mismatches() -> None:
    selected_profile = profile(
        network={"required_interfaces": ["wlan0"], "allowed_transport_types": ["WIFI"]},
        graphics={"allowed_gles_vendors": ["ARM"], "allowed_gles_renderer_patterns": ["Mali"]},
        input={"minimum_device_count": 1},
    )
    comparisons = compare_profile(
        {}, None, None, selected_profile,
        network=phase5_network("permission_denied_phase5"),
        graphics=phase5_graphics("unsupported_commands_phase5"),
        input_devices=phase5_input("permission_denied_phase5"),
    )

    assert {comparison.status for comparison in comparisons if comparison.category in {"network", "graphics", "input"}} == {"not_evaluated"}


def test_phase5_profile_validation_rejects_invalid_values_without_defaults() -> None:
    with pytest.raises(ProfileValidationError):
        profile(network={"allowed_transport_types": ["CARRIER_PIGEON"]})
    with pytest.raises(ProfileValidationError):
        profile(graphics={"allowed_gles_renderer_patterns": ["("]})
    with pytest.raises(ProfileValidationError):
        profile(input={"required_device_classes": ["TELEPATHY"]})
    with pytest.raises(ProfileValidationError):
        profile(memory={"minimum_total_kb": 2048, "maximum_total_kb": 1024})


def test_phase5_command_surface_is_exact_and_reuses_no_full_getprop() -> None:
    assert [spec.arguments for spec in NETWORK_COMMANDS] == [
        ("dumpsys", "connectivity"),
        ("ip", "link"),
        ("cmd", "wifi", "status"),
        ("settings", "get", "global", "airplane_mode_on"),
        ("settings", "get", "global", "bluetooth_on"),
    ]
    assert [spec.arguments for spec in GRAPHICS_COMMANDS] == [
        ("dumpsys", "SurfaceFlinger"),
        ("dumpsys", "gpu"),
        ("getprop", "ro.hardware.egl"),
        ("getprop", "ro.hardware.vulkan"),
    ]
    assert [spec.arguments for spec in INPUT_COMMANDS] == [
        ("dumpsys", "input"),
        ("cat", "/proc/bus/input/devices"),
    ]
    assert [spec.arguments for spec in MEMORY_COMMANDS] == [
        ("cat", "/proc/meminfo"),
        ("cat", "/proc/swaps"),
        ("getprop", "ro.config.low_ram"),
    ]
    all_specs = (*NETWORK_COMMANDS, *GRAPHICS_COMMANDS, *INPUT_COMMANDS, *MEMORY_COMMANDS)
    assert all(spec.arguments != ("getprop",) for spec in all_specs)
    assert not CaptureOptions(skip_network=True, skip_graphics=True, skip_input=True, skip_memory=True).skip_display


def test_phase5_redaction_removes_wireless_identifiers_without_hiding_constants() -> None:
    text = (
        "SSID: \"synthetic-home-network\"\n"
        "LinkAddresses: [ 192.168.50.23/24, fe80::1234:5678:9abc:def0/64 ]\n"
        "    inet6 fe80::aaaa:bbbb:cccc:dddd/64\n"
        "network id: synthetic-network-0001\n"
        "state UP mtu 1500\n"
        "GLES: ARM, Mali-G715, OpenGL ES 3.2\n"
    )
    redacted = redact_text(text)

    assert "synthetic-home-network" not in redacted
    assert "fe80::1234:5678:9abc:def0" not in redacted
    assert "fe80::aaaa:bbbb:cccc:dddd" not in redacted
    assert "192.168.50.23" not in redacted
    assert "synthetic-network-0001" not in redacted
    assert "state UP mtu 1500" in redacted
    assert "Mali-G715" in redacted


def _result(command: tuple[str, ...], stdout: str) -> CommandResult:
    return CommandResult(command=command, exit_code=0, stdout=stdout, stderr="", duration_ms=1, timed_out=False)


def _phase5_commands() -> list[EvidenceCommand]:
    family = "pixel_phase5"
    mapping = {
        "network.connectivity": "network_connectivity.txt", "network.ip_link": "network_ip_link.txt", "network.wifi_status": "network_wifi_status.txt", "network.airplane_mode": "network_airplane_mode.txt", "network.bluetooth_state": "network_bluetooth_state.txt",
        "graphics.surface_flinger": "graphics_surface_flinger.txt", "graphics.gpu": "graphics_gpu.txt", "graphics.egl_property": "graphics_egl_property.txt", "graphics.vulkan_property": "graphics_vulkan_property.txt",
        "input.dumpsys": "input_dumpsys.txt", "input.proc_devices": "input_proc_devices.txt",
        "memory.proc_meminfo": "memory_proc_meminfo.txt", "memory.proc_swaps": "memory_proc_swaps.txt", "memory.low_ram_property": "memory_low_ram_property.txt",
    }
    return [
        EvidenceCommand(command_id, command_id.split(".", 1)[0], _result(("adb", "-s", "fixture-phase5-serial", "shell", command_id), fixture(family, file_name)))
        for command_id, file_name in mapping.items()
    ]


def test_schema_five_bundle_replays_offline_and_detects_tampering(tmp_path: Path) -> None:
    states = {name: "not_evaluated" for name in ("display", "telephony", "packages", "magisk", "runtime_markers", "camera", "sensors", "hal", "audio", "battery", "thermal", "storage")}
    states.update({name: "observed" for name in ("network", "graphics", "input", "memory")})
    bundle = write_evidence_bundle(tmp_path / "bundle", "fixture-phase5-serial", _phase5_commands(), collector_states=states, schema_version="5.0")
    outcome = analyze_bundle(bundle, tmp_path / "report")
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))

    assert load_evidence_bundle(bundle)["schema_version"] == "5.0"
    assert report["sections"]["network"]["status"] == "observed"
    assert report["sections"]["graphics"]["data"]["gles_renderer"] == "Mali-G715-Immortalis MC11"
    assert report["sections"]["memory"]["data"]["total_kb"] == 12197892
    raw = next((bundle / "raw").glob("memory_proc_meminfo*.stdout.txt"))
    raw.write_text(raw.read_text(encoding="utf-8") + "tamper", encoding="utf-8")
    with pytest.raises(BundleIntegrityError):
        load_evidence_bundle(bundle)


def test_schema_five_report_and_artifacts_redact_sensitive_phase5_values(tmp_path: Path) -> None:
    commands = _phase5_commands()
    states = {name: "not_evaluated" for name in ("display", "telephony", "packages", "magisk", "runtime_markers", "camera", "sensors", "hal", "audio", "battery", "thermal", "storage", "graphics", "input", "memory")}
    states["network"] = "observed"
    bundle = write_evidence_bundle(tmp_path / "bundle", "fixture-phase5-serial", commands, collector_states=states, schema_version="5.0")
    analyze_bundle(bundle, tmp_path / "report")

    for path in list(bundle.rglob("*")) + list((tmp_path / "report").rglob("*")):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert "fixture-phase5-serial" not in text
            assert "SyntheticHomeNet" not in text
            assert "02:11:22:33:44:55" not in text
            assert "192.168.50.23" not in text


def test_older_schema_bundles_never_report_phase5_sections_as_observed(tmp_path: Path) -> None:
    bundle = write_evidence_bundle(
        tmp_path / "bundle",
        "fixture-phase5-serial",
        [
            EvidenceCommand(
                "properties.getprop",
                "properties",
                _result(("adb", "-s", "fixture-phase5-serial", "shell", "getprop"), "[ro.product.model]: [Synthetic]\n"),
            )
        ],
        schema_version="4.0",
    )
    outcome = analyze_bundle(bundle, tmp_path / "report")
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))

    assert report["bundle_schema_version"] == "4.0"
    for section in ("network", "graphics", "input", "memory"):
        assert report["sections"][section]["status"] == "not_evaluated"
    assert outcome.collector_errors == 0


@pytest.mark.parametrize("family", PHASE5_FAMILIES)
def test_all_phase5_fixtures_are_parser_safe_and_deterministic(family: str) -> None:
    first = (phase5_network(family), phase5_graphics(family), phase5_input(family), phase5_memory(family))
    second = (phase5_network(family), phase5_graphics(family), phase5_input(family), phase5_memory(family))

    assert tuple(asdict(item) for item in first) == tuple(asdict(item) for item in second)
