from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from device_audit.analysis import analyze_bundle
from device_audit.bundle import BundleIntegrityError, load_evidence_bundle, write_evidence_bundle
from device_audit.capture import CaptureOptions
from device_audit.collectors import AUDIO_COMMANDS, BATTERY_COMMANDS, STORAGE_COMMANDS, THERMAL_COMMANDS
from device_audit.models import CommandResult, EvidenceCommand
from device_audit.parsers import (
    parse_audio_info,
    parse_battery_info,
    parse_storage_info,
    parse_thermal_info,
)
from device_audit.profiles import ProfileValidationError, profile_from_mapping
from device_audit.redaction import redact_text
from device_audit.rules import compare_profile, evaluate_profile


FIXTURES = Path(__file__).parent / "fixtures"
PHASE4_FAMILIES = (
    "pixel_phase4",
    "samsung_phase4",
    "vmos_phase4",
    "aosp_emulator_phase4",
    "lineage_phase4",
    "malformed_phase4",
    "permission_denied_phase4",
    "unsupported_commands_phase4",
)
PHASE4_ARTIFACTS = (
    "audio_dumpsys_audio.txt",
    "audio_audio_flinger.txt",
    "audio_audio_policy.txt",
    "audio_policy_ports.txt",
    "audio_policy_patches.txt",
    "battery_dumpsys_battery.txt",
    "battery_properties.txt",
    "battery_cmd_status.txt",
    "battery_cmd_health.txt",
    "battery_cmd_level.txt",
    "battery_cmd_plugged.txt",
    "battery_cmd_current.txt",
    "battery_cmd_temperature.txt",
    "battery_cmd_counter.txt",
    "battery_cmd_charging_status.txt",
    "thermal_service.txt",
    "thermal_cmd_dump.txt",
    "thermal_power.txt",
    "thermal_deviceidle.txt",
    "thermal_power_mode.txt",
    "thermal_fixed_performance_mode.txt",
    "storage_df_k.txt",
    "storage_mount.txt",
    "storage_proc_mounts.txt",
    "storage_proc_filesystems.txt",
    "storage_proc_partitions.txt",
    "storage_dumpsys_mount.txt",
    "storage_volumes.txt",
    "storage_disks.txt",
    "storage_primary_uuid.txt",
)


def fixture(family: str, name: str) -> str:
    return (FIXTURES / family / name).read_text(encoding="utf-8")


def phase4_audio(family: str = "pixel_phase4"):
    return parse_audio_info(
        fixture(family, "audio_dumpsys_audio.txt"),
        fixture(family, "audio_audio_flinger.txt"),
        fixture(family, "audio_audio_policy.txt"),
        fixture(family, "audio_policy_ports.txt"),
        fixture(family, "audio_policy_patches.txt"),
    )


def phase4_battery(family: str = "pixel_phase4"):
    return parse_battery_info(
        fixture(family, "battery_dumpsys_battery.txt"),
        fixture(family, "battery_properties.txt"),
        {
            "status": fixture(family, "battery_cmd_status.txt"),
            "health": fixture(family, "battery_cmd_health.txt"),
            "level": fixture(family, "battery_cmd_level.txt"),
            "plugged": fixture(family, "battery_cmd_plugged.txt"),
            "current now": f"{fixture(family, 'battery_cmd_current.txt').strip()} uA",
            "temperature": f"{fixture(family, 'battery_cmd_temperature.txt').strip()} tenths C",
            "charge counter": f"{fixture(family, 'battery_cmd_counter.txt').strip()} uAh",
            "charging": fixture(family, "battery_cmd_charging_status.txt"),
        },
    )


def phase4_thermal(family: str = "pixel_phase4"):
    return parse_thermal_info(
        fixture(family, "thermal_service.txt"),
        fixture(family, "thermal_power.txt"),
        fixture(family, "thermal_deviceidle.txt"),
        fixture(family, "thermal_cmd_dump.txt"),
        fixture(family, "thermal_power_mode.txt"),
        fixture(family, "thermal_fixed_performance_mode.txt"),
    )


def phase4_storage(family: str = "pixel_phase4"):
    return parse_storage_info(
        fixture(family, "storage_df_k.txt"),
        fixture(family, "storage_mount.txt"),
        fixture(family, "storage_proc_mounts.txt"),
        fixture(family, "storage_proc_filesystems.txt"),
        fixture(family, "storage_proc_partitions.txt"),
        fixture(family, "storage_dumpsys_mount.txt"),
        fixture(family, "storage_volumes.txt"),
        fixture(family, "storage_disks.txt"),
        fixture(family, "storage_primary_uuid.txt"),
        {"ro.crypto.state": "encrypted", "ro.crypto.metadata.enabled": "true"},
    )


def profile(**sections: object):
    return profile_from_mapping({"schema_version": "4.0", "name": "Synthetic Phase 4", **sections})


def test_phase4_fixture_families_declare_every_collector_artifact() -> None:
    for family in PHASE4_FAMILIES:
        assert {path.name for path in (FIXTURES / family).iterdir()} == set(PHASE4_ARTIFACTS)


def test_audio_parser_normalizes_devices_formats_counts_unicode_and_crlf() -> None:
    audio = phase4_audio()
    unicode_audio = phase4_audio("lineage_phase4")
    crlf = parse_audio_info(fixture("pixel_phase4", "audio_dumpsys_audio.txt").replace("\n", "\r\n"))

    assert [device.direction for device in audio.output_devices] == ["OUTPUT"]
    assert [device.role for device in audio.input_devices] == ["SOURCE"]
    assert audio.output_devices[0].sample_rates == (44100, 48000)
    assert audio.active_patch_count == 1
    assert audio.effect_count == 3
    assert unicode_audio.output_devices[0].product_name == "Loa thử nghiệm"
    assert crlf.output_devices[0].device_type == "AUDIO_DEVICE_OUT_SPEAKER"


def test_audio_parser_keeps_unknown_and_unsupported_data_inventory_only() -> None:
    malformed = phase4_audio("malformed_phase4")
    denied = phase4_audio("permission_denied_phase4")
    unsupported = phase4_audio("unsupported_commands_phase4")

    assert not malformed.output_devices and not malformed.input_devices
    assert malformed.parse_warnings
    assert denied.service_status == "unavailable"
    assert unsupported.service_status == "unavailable"


def test_battery_parser_normalizes_values_without_guessing_units() -> None:
    battery = phase4_battery()
    malformed = phase4_battery("malformed_phase4")
    vmos = phase4_battery("vmos_phase4")

    assert battery.battery_status == "CHARGING"
    assert battery.plugged_source == "USB"
    assert battery.level_percent == 80
    assert battery.temperature_c == 25.0
    assert battery.current_now_ua == -250000
    assert vmos.battery_status == "DISCHARGING"
    assert malformed.voltage_mv is None
    assert any("unknown units" in warning for warning in malformed.parse_warnings)


def test_thermal_parser_normalizes_sensors_power_state_and_vendor_uncertainty() -> None:
    thermal = phase4_thermal()
    malformed = phase4_thermal("malformed_phase4")

    assert {sensor.type for sensor in thermal.temperature_sensors} >= {"CPU", "BATTERY", "MODEM", "SKIN"}
    assert thermal.current_thermal_severity == "NONE"
    assert thermal.wakefulness == "AWAKE"
    assert thermal.cooling_devices[0].current_value == 1
    assert any(sensor.type == "UNKNOWN" and sensor.temperature_c is None for sensor in malformed.temperature_sensors)


def test_storage_parser_normalizes_mounts_volumes_and_properties() -> None:
    storage = phase4_storage()
    malformed = phase4_storage("malformed_phase4")

    data_mount = next(mount for mount in storage.mounts if mount.target == "/data")
    assert data_mount.available_kb == 80000
    assert data_mount.read_only is False
    assert {volume.type for volume in storage.volumes} == {"PRIVATE", "PUBLIC", "EMULATED"}
    assert {filesystem.name for filesystem in storage.supported_filesystems} >= {"ext4", "f2fs", "erofs"}
    assert storage.encryption_state == "encrypted"
    assert malformed.parse_warnings


def test_phase4_profile_sections_are_inventory_only_when_absent_or_empty() -> None:
    observations = (phase4_audio(), phase4_battery(), phase4_thermal(), phase4_storage())
    for selected_profile in (profile(), profile(audio={}, battery={}, thermal={}, storage={})):
        comparisons = compare_profile({}, None, None, selected_profile, audio=observations[0], battery=observations[1], thermal=observations[2], storage=observations[3])
        assert not [comparison for comparison in comparisons if comparison.category in {"audio", "battery", "thermal", "storage"}]
        assert evaluate_profile({}, None, None, selected_profile, audio=observations[0], battery=observations[1], thermal=observations[2], storage=observations[3]) == []


def test_phase4_profile_rules_are_explicit_deterministic_and_no_extra_inventory_mismatch() -> None:
    selected_profile = profile(
        audio={
            "minimum_output_device_count": 1,
            "required_output_device_types": ["AUDIO_DEVICE_OUT_SPEAKER"],
            "required_sample_rates": [48000],
        },
        battery={"require_present": True, "allowed_health": ["GOOD"], "minimum_level_percent": 5},
        thermal={"required_sensor_types": ["CPU", "BATTERY"], "allowed_current_severity": ["NONE", "LIGHT"]},
        storage={"required_filesystem_types": ["f2fs"], "required_mount_points": ["/data"], "minimum_data_available_kb": 1024},
    )
    comparisons = compare_profile({}, None, None, selected_profile, audio=phase4_audio(), battery=phase4_battery(), thermal=phase4_thermal(), storage=phase4_storage())

    assert comparisons
    assert {item.status for item in comparisons if item.category in {"audio", "battery", "thermal", "storage"}} == {"matched"}
    assert evaluate_profile({}, None, None, selected_profile, audio=phase4_audio(), battery=phase4_battery(), thermal=phase4_thermal(), storage=phase4_storage()) == []


def test_phase4_profile_mismatches_only_declared_expectations() -> None:
    selected_profile = profile(
        audio={"minimum_output_device_count": 3},
        battery={"allowed_health": ["COLD"]},
        thermal={"maximum_sensor_temperature_c": {"CPU": 40}},
        storage={"require_data_mount_read_write": False},
    )
    findings = evaluate_profile({}, None, None, selected_profile, audio=phase4_audio(), battery=phase4_battery(), thermal=phase4_thermal(), storage=phase4_storage())

    assert [finding.id for finding in findings] == [
        "AUDIO_PROFILE_MISMATCH",
        "BATTERY_PROFILE_MISMATCH",
        "THERMAL_PROFILE_MISMATCH",
        "STORAGE_PROFILE_MISMATCH",
    ]


def test_permission_and_unsupported_observations_do_not_create_false_mismatches() -> None:
    selected_profile = profile(audio={"minimum_output_device_count": 1}, battery={"require_present": True})
    comparisons = compare_profile(
        {}, None, None, selected_profile,
        audio=phase4_audio("permission_denied_phase4"),
        battery=phase4_battery("unsupported_commands_phase4"),
    )

    assert {comparison.status for comparison in comparisons if comparison.category in {"audio", "battery"}} == {"not_evaluated"}


def test_phase4_profile_validation_rejects_invalid_values_without_defaults() -> None:
    with pytest.raises(ProfileValidationError):
        profile(audio={"required_sample_rates": [0]})
    with pytest.raises(ProfileValidationError):
        profile(battery={"allowed_health": ["EXCELLENT"]})
    with pytest.raises(ProfileValidationError):
        profile(thermal={"required_sensor_types": ["HOT"]})
    with pytest.raises(ProfileValidationError):
        profile(storage={"allowed_volume_types": ["MYSTERY"]})


def test_phase4_command_surface_is_exact_and_reuses_getprop() -> None:
    assert [spec.arguments for spec in AUDIO_COMMANDS] == [
        ("dumpsys", "audio"),
        ("dumpsys", "media.audio_flinger"),
        ("dumpsys", "media.audio_policy"),
        ("cmd", "media.audio_policy", "list-audio-ports"),
        ("cmd", "media.audio_policy", "list-audio-patches"),
    ]
    assert [spec.arguments for spec in BATTERY_COMMANDS][0] == ("dumpsys", "battery")
    assert [spec.arguments for spec in THERMAL_COMMANDS][-1] == ("cmd", "power", "get-fixed-performance-mode-enabled")
    assert [spec.arguments for spec in STORAGE_COMMANDS] == [
        ("df", "-k"), ("mount",), ("cat", "/proc/mounts"), ("cat", "/proc/filesystems"),
        ("cat", "/proc/partitions"), ("dumpsys", "mount"), ("sm", "list-volumes", "all"),
        ("sm", "list-disks"), ("sm", "get-primary-storage-uuid"),
    ]
    assert all(spec.arguments != ("getprop",) for spec in STORAGE_COMMANDS)
    assert not CaptureOptions(skip_audio=True, skip_battery=True, skip_thermal=True, skip_storage=True).skip_display


def test_phase4_redaction_removes_contextual_identifiers_without_hiding_constants() -> None:
    text = "battery serial: synthetic-battery-000001\nvolume id: public:179,65\nPID: 1234\nAUDIO_DEVICE_OUT_SPEAKER\n/data/user/0/com.synthetic.app/files/x\n"
    redacted = redact_text(text)

    assert "synthetic-battery-000001" not in redacted
    assert "public:179,65" not in redacted
    assert "1234" not in redacted
    assert "AUDIO_DEVICE_OUT_SPEAKER" in redacted
    assert "com.synthetic.app" not in redacted


def _result(command: tuple[str, ...], stdout: str) -> CommandResult:
    return CommandResult(command=command, exit_code=0, stdout=stdout, stderr="", duration_ms=1, timed_out=False)


def _phase4_commands() -> list[EvidenceCommand]:
    family = "pixel_phase4"
    mapping = {
        "audio.dumpsys_audio": "audio_dumpsys_audio.txt", "audio.audio_flinger": "audio_audio_flinger.txt", "audio.audio_policy": "audio_audio_policy.txt", "audio.policy_ports": "audio_policy_ports.txt", "audio.policy_patches": "audio_policy_patches.txt",
        "battery.dumpsys_battery": "battery_dumpsys_battery.txt", "battery.properties": "battery_properties.txt", "battery.cmd_status": "battery_cmd_status.txt", "battery.cmd_health": "battery_cmd_health.txt", "battery.cmd_level": "battery_cmd_level.txt", "battery.cmd_plugged": "battery_cmd_plugged.txt", "battery.cmd_current": "battery_cmd_current.txt", "battery.cmd_temperature": "battery_cmd_temperature.txt", "battery.cmd_counter": "battery_cmd_counter.txt", "battery.cmd_charging_status": "battery_cmd_charging_status.txt",
        "thermal.service": "thermal_service.txt", "thermal.cmd_dump": "thermal_cmd_dump.txt", "thermal.power": "thermal_power.txt", "thermal.deviceidle": "thermal_deviceidle.txt", "thermal.power_mode": "thermal_power_mode.txt", "thermal.fixed_performance_mode": "thermal_fixed_performance_mode.txt",
        "storage.df_k": "storage_df_k.txt", "storage.mount": "storage_mount.txt", "storage.proc_mounts": "storage_proc_mounts.txt", "storage.proc_filesystems": "storage_proc_filesystems.txt", "storage.proc_partitions": "storage_proc_partitions.txt", "storage.dumpsys_mount": "storage_dumpsys_mount.txt", "storage.volumes": "storage_volumes.txt", "storage.disks": "storage_disks.txt", "storage.primary_uuid": "storage_primary_uuid.txt",
    }
    return [
        EvidenceCommand(command_id, command_id.split(".", 1)[0], _result(("adb", "-s", "fixture-phase4-serial", "shell", command_id), fixture(family, file_name)))
        for command_id, file_name in mapping.items()
    ]


def test_schema_four_bundle_replays_offline_and_detects_tampering(tmp_path: Path) -> None:
    states = {name: "not_evaluated" for name in ("display", "telephony", "packages", "magisk", "runtime_markers", "camera", "sensors", "hal")}
    states.update({name: "observed" for name in ("audio", "battery", "thermal", "storage")})
    bundle = write_evidence_bundle(tmp_path / "bundle", "fixture-phase4-serial", _phase4_commands(), collector_states=states, schema_version="4.0")
    outcome = analyze_bundle(bundle, tmp_path / "report")
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))

    assert load_evidence_bundle(bundle)["schema_version"] == "4.0"
    assert report["sections"]["storage"]["status"] == "observed"
    assert report["sections"]["audio"]["data"]["output_devices"][0]["address"] == "built-in"
    raw = next((bundle / "raw").glob("storage_volumes*.stdout.txt"))
    raw.write_text(raw.read_text(encoding="utf-8") + "tamper", encoding="utf-8")
    with pytest.raises(BundleIntegrityError):
        load_evidence_bundle(bundle)


def test_schema_four_report_and_artifacts_redact_sensitive_phase4_values(tmp_path: Path) -> None:
    commands = _phase4_commands()
    commands[0] = EvidenceCommand(
        commands[0].id,
        commands[0].section,
        _result(("adb", "-s", "fixture-phase4-serial", "shell", "dumpsys", "audio"), "audio session id: synthetic-session-000001\n"),
    )
    states = {name: "not_evaluated" for name in ("display", "telephony", "packages", "magisk", "runtime_markers", "camera", "sensors", "hal", "battery", "thermal", "storage")}
    states["audio"] = "observed"
    bundle = write_evidence_bundle(tmp_path / "bundle", "fixture-phase4-serial", commands, collector_states=states, schema_version="4.0")
    analyze_bundle(bundle, tmp_path / "report")

    for path in list(bundle.rglob("*")) + list((tmp_path / "report").rglob("*")):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert "fixture-phase4-serial" not in text
            assert "synthetic-session-000001" not in text


@pytest.mark.parametrize("family", PHASE4_FAMILIES)
def test_all_phase4_fixtures_are_parser_safe_and_deterministic(family: str) -> None:
    first = (phase4_audio(family), phase4_battery(family), phase4_thermal(family), phase4_storage(family))
    second = (phase4_audio(family), phase4_battery(family), phase4_thermal(family), phase4_storage(family))

    assert tuple(asdict(item) for item in first) == tuple(asdict(item) for item in second)
