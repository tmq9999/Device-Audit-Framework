from __future__ import annotations

import json
from pathlib import Path

import pytest

import device_audit.capture as capture_module
from device_audit.analysis import analyze_bundle
from device_audit.bundle import BundleIntegrityError, load_evidence_bundle, write_evidence_bundle
from device_audit.capture import CaptureOptions, capture_evidence
from device_audit.cli import build_parser
from device_audit.models import CommandResult, EvidenceCommand
from device_audit.parsers import parse_camera_info, parse_hal_info, parse_sensor_info
from device_audit.profiles import ProfileValidationError, profile_from_mapping
from device_audit.redaction import redact_text
from device_audit.rules import compare_profile, evaluate_profile

FIXTURES = Path(__file__).parent / "fixtures"
PHASE3_FAMILIES = (
    "pixel_phase3",
    "samsung_phase3",
    "vmos_phase3",
    "aosp_emulator_phase3",
    "lineage_phase3",
    "malformed_phase3",
    "permission_denied_phase3",
)


def fixture(family: str, name: str) -> str:
    return (FIXTURES / family / name).read_text(encoding="utf-8")


def result(
    command: tuple[str, ...],
    stdout: str = "",
    *,
    stderr: str = "",
    exit_code: int | None = 0,
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=1,
        timed_out=timed_out,
    )


def _camera(family: str):
    return parse_camera_info(
        fixture(family, "camera_media_camera.txt"),
        fixture(family, "camera_cmd_list.txt"),
        fixture(family, "camera_cmd_dump.txt"),
    )


def _sensors(family: str):
    return parse_sensor_info(fixture(family, "sensors_sensorservice.txt"))


def _hal(family: str):
    return parse_hal_info(
        fixture(family, "hal_lshal.txt"),
        fixture(family, "hal_lshal_interfaces.txt"),
        fixture(family, "hal_dumpsys_services.txt"),
        "0 android.hardware.camera.provider@2.7::ICameraProvider/internal/0: [synthetic]\n",
        {"ro.hardware.camera": "synthetic", "ro.product.model": "Inventory only"},
    )


def _profile(**sections: object):
    return profile_from_mapping({"schema_version": "3.0", "name": "Synthetic", **sections})


def test_camera_parser_extracts_logical_physical_and_bounded_stream_summary() -> None:
    camera = _camera("pixel_phase3")

    assert camera.camera_count == 2
    assert camera.logical_camera_count == 1
    assert camera.physical_camera_count == 2
    assert [item.facing for item in camera.cameras] == ["back", "front"]
    assert camera.cameras[0].hardware_level == "FULL"
    assert camera.cameras[1].hardware_level == "LEVEL_3"
    assert camera.cameras[0].output_format_count == 3
    assert camera.cameras[0].representative_output_sizes == ("4080x3072", "3840x2160", "1920x1080")
    assert camera.concurrent_combinations == (("0", "1"),)
    assert camera.active_client_count == 1


def test_camera_parser_tolerates_legacy_truncated_and_unsupported_output() -> None:
    legacy = _camera("vmos_phase3")
    malformed = _camera("malformed_phase3")
    denied = _camera("permission_denied_phase3")

    assert legacy.cameras[0].hardware_level == "LEGACY"
    assert malformed.cameras[0].hardware_level == "UNKNOWN"
    assert malformed.cameras[0].orientation is None
    assert denied.camera_count == 0
    assert denied.service_status == "unknown" or denied.service_status == "unavailable"


def test_sensor_parser_normalizes_standard_vendor_and_unicode_entries() -> None:
    pixel = _sensors("pixel_phase3")
    lineage = _sensors("lineage_phase3")

    assert pixel.sensor_count == 4
    assert pixel.type_counts["android.sensor.accelerometer"] == 1
    assert pixel.wakeup_sensor_count == 2
    assert pixel.active_sensor_count == 2
    assert pixel.active_connection_count == 1
    assert lineage.sensors[0].name.startswith("Cảm biến")
    assert lineage.sensors[1].normalized_type == "org.synthetic.sensor.custom"


def test_sensor_parser_handles_malformed_blank_crlf_and_permission_data() -> None:
    malformed = _sensors("malformed_phase3")
    crlf = parse_sensor_info(fixture("pixel_phase3", "sensors_sensorservice.txt").replace("\n", "\r\n"))
    blank = parse_sensor_info("")
    denied = _sensors("permission_denied_phase3")

    assert malformed.sensor_count == 3
    assert any("invalid" in warning for warning in malformed.parse_warnings)
    assert crlf.sensor_count == 4
    assert blank.sensor_count == 0
    assert denied.sensor_count == 0


def test_hal_parser_recognizes_hidl_aidl_passthrough_lazy_and_reused_sources() -> None:
    hal = _hal("pixel_phase3")

    assert hal.hidl_count >= 3
    assert hal.aidl_count >= 1
    assert hal.passthrough_count == 1
    assert hal.binderized_count >= 2
    assert hal.lazy_count == 1
    assert "android.hardware.camera" in hal.families
    assert hal.binder_service_count == 1
    assert hal.hal_properties == {"ro.hardware.camera": "synthetic"}


def test_hal_parser_handles_partial_malformed_and_permission_output() -> None:
    malformed = _hal("malformed_phase3")
    denied = _hal("permission_denied_phase3")

    assert malformed.hal_count >= 1
    assert denied.hal_count == 0
    assert denied.parse_warnings


@pytest.mark.parametrize("family", PHASE3_FAMILIES)
def test_every_phase3_fixture_family_is_parser_regression_coverage(family: str) -> None:
    camera = _camera(family)
    sensors = _sensors(family)
    hal = _hal(family)

    assert camera.camera_count >= 0
    assert sensors.sensor_count >= 0
    assert hal.hal_count >= 0


def test_phase3_profile_validation_rejects_invalid_expectations() -> None:
    with pytest.raises(ProfileValidationError, match="required_facing"):
        _profile(camera={"required_facing": ["sideways"]})
    with pytest.raises(ProfileValidationError, match="allowed_hardware_levels"):
        _profile(camera={"allowed_hardware_levels": ["FUTURE"]})
    with pytest.raises(ProfileValidationError, match="minimum_sensor_count"):
        _profile(sensors={"minimum_sensor_count": -1})
    with pytest.raises(ProfileValidationError, match="allowed_transports"):
        _profile(hal={"allowed_transports": ["socket"]})


def test_absent_phase3_profile_expectations_remain_inventory_only() -> None:
    findings = evaluate_profile(
        {},
        None,
        None,
        _profile(),
        camera=_camera("pixel_phase3"),
        sensors=_sensors("pixel_phase3"),
        hal=_hal("pixel_phase3"),
    )

    assert findings == []


def test_phase3_rules_match_explicit_expectations_without_penalizing_extra_inventory() -> None:
    profile = _profile(
        camera={
            "minimum_camera_count": 2,
            "required_facing": ["front", "back"],
            "required_camera_ids": ["0", "1"],
            "allowed_hardware_levels": ["FULL", "LEVEL_3"],
            "required_capabilities": ["BACKWARD_COMPATIBLE", "LOGICAL_MULTI_CAMERA"],
        },
        sensors={
            "minimum_sensor_count": 2,
            "required_types": ["android.sensor.accelerometer", "android.sensor.gyroscope"],
            "allowed_vendors": ["Google Synthetic", "Bosch Synthetic"],
        },
        hal={
            "required_interfaces": ["android.hardware.camera.provider"],
            "required_families": ["android.hardware.camera", "android.hardware.sensors"],
            "allowed_transports": ["hwbinder", "binder", "passthrough"],
        },
    )

    comparisons = compare_profile(
        {},
        None,
        None,
        profile,
        camera=_camera("pixel_phase3"),
        sensors=_sensors("pixel_phase3"),
        hal=_hal("pixel_phase3"),
    )

    assert comparisons
    phase3_comparisons = [
        comparison for comparison in comparisons if comparison.category in {"camera", "sensors", "hal"}
    ]
    assert {comparison.status for comparison in phase3_comparisons} == {"matched"}


def test_phase3_rules_report_only_declared_mismatches() -> None:
    profile = _profile(
        camera={"minimum_camera_count": 3, "required_facing": ["external"]},
        sensors={"required_types": ["android.sensor.proximity"], "allowed_vendors": ["Other"]},
        hal={
            "required_interfaces": ["android.hardware.missing"],
            "required_families": ["android.hardware.missing"],
            "allowed_transports": ["passthrough"],
        },
    )
    findings = evaluate_profile(
        {},
        None,
        None,
        profile,
        camera=_camera("pixel_phase3"),
        sensors=_sensors("pixel_phase3"),
        hal=_hal("pixel_phase3"),
    )

    assert {finding.id for finding in findings} == {
        "CAMERA_PROFILE_MISMATCH",
        "SENSORS_PROFILE_MISMATCH",
        "HAL_PROFILE_MISMATCH",
    }
    assert not any(
        word in " ".join(finding.summary for finding in findings).lower()
        for word in ("authentic", "stealth", "integrity", "risk", "eligibility", "offer")
    )


def test_schema_three_bundle_replays_offline_with_bounded_phase3_report_and_redaction(tmp_path: Path) -> None:
    serial = "fixture-phase3-serial"
    root = ("adb", "-s", serial, "shell")
    bundle = write_evidence_bundle(
        tmp_path / "bundle",
        serial,
        [
            EvidenceCommand("properties.getprop", "properties", result((*root, "getprop"), "[ro.hardware.camera]: [synthetic]\n")),
            EvidenceCommand("runtime.services", "runtime_markers", result((*root, "service", "list"), "0 android.hardware.camera.provider@2.7::ICameraProvider/internal/0: [synthetic]\n")),
            EvidenceCommand("camera.media_camera", "camera", result((*root, "dumpsys", "media.camera"), fixture("pixel_phase3", "camera_media_camera.txt") + "Client ID: CAMERA-CLIENT-SECRET-0001\n")),
            EvidenceCommand("camera.cmd_list", "camera", result((*root, "cmd", "media.camera", "list"), fixture("pixel_phase3", "camera_cmd_list.txt"))),
            EvidenceCommand("camera.cmd_dump", "camera", result((*root, "cmd", "media.camera", "dump"), fixture("pixel_phase3", "camera_cmd_dump.txt"))),
            EvidenceCommand("sensors.sensorservice", "sensors", result((*root, "dumpsys", "sensorservice"), fixture("pixel_phase3", "sensors_sensorservice.txt"))),
            EvidenceCommand("hal.lshal", "hal", result((*root, "lshal"), fixture("pixel_phase3", "hal_lshal.txt"))),
            EvidenceCommand("hal.lshal_interfaces", "hal", result((*root, "lshal", "-i"), fixture("pixel_phase3", "hal_lshal_interfaces.txt"))),
            EvidenceCommand("hal.dumpsys_services", "hal", result((*root, "dumpsys", "-l"), fixture("pixel_phase3", "hal_dumpsys_services.txt"))),
        ],
        collector_states={
            "display": "not_evaluated",
            "telephony": "not_evaluated",
            "packages": "not_evaluated",
            "magisk": "not_evaluated",
            "runtime_markers": "observed",
            "camera": "observed",
            "sensors": "observed",
            "hal": "observed",
        },
        schema_version="3.0",
    )

    first = analyze_bundle(bundle, tmp_path / "report-one")
    second = analyze_bundle(bundle, tmp_path / "report-two")
    first_report = json.loads(first.report_path.read_text(encoding="utf-8"))
    second_report = json.loads(second.report_path.read_text(encoding="utf-8"))
    first_report.pop("generated_at")
    second_report.pop("generated_at")

    assert load_evidence_bundle(bundle)["schema_version"] == "3.0"
    assert first_report == second_report
    assert first_report["sections"]["camera"]["data"]["camera_count"] == 2
    assert first_report["sections"]["sensors"]["data"]["sensor_count"] == 4
    assert first_report["sections"]["hal"]["profile_comparison_status"] == "not_evaluated"
    markdown = (tmp_path / "report-one" / "report.md").read_text(encoding="utf-8")
    assert "## Camera Inventory" in markdown
    assert "## Sensor Inventory" in markdown
    assert "## HAL and Native Services" in markdown
    serialized = "\n".join(path.read_text(encoding="utf-8") for path in bundle.rglob("*") if path.is_file())
    assert serial not in serialized
    assert "CAMERA-CLIENT-SECRET-0001" not in serialized


def test_schema_three_bundle_rejects_undeclared_raw_artifact_and_future_schema(tmp_path: Path) -> None:
    bundle = write_evidence_bundle(
        tmp_path / "bundle",
        "fixture-serial",
        [EvidenceCommand("camera.cmd_list", "camera", result(("adb", "shell", "cmd", "media.camera", "list"), "0\n"))],
        collector_states={
            "display": "not_evaluated",
            "telephony": "not_evaluated",
            "packages": "not_evaluated",
            "magisk": "not_evaluated",
            "runtime_markers": "not_evaluated",
            "camera": "observed",
            "sensors": "not_evaluated",
            "hal": "not_evaluated",
        },
        schema_version="3.0",
    )
    (bundle / "raw" / "undeclared.txt").write_text("synthetic", encoding="utf-8")

    with pytest.raises(BundleIntegrityError, match="undeclared"):
        load_evidence_bundle(bundle)

    (bundle / "raw" / "undeclared.txt").unlink()
    evidence = json.loads((bundle / "evidence.json").read_text(encoding="utf-8"))
    evidence["schema_version"] = "99.0"
    (bundle / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(BundleIntegrityError, match="unsupported"):
        load_evidence_bundle(bundle)


def test_capture_schema_three_skip_flags_omit_new_collectors(monkeypatch, tmp_path: Path) -> None:
    serial = "fixture-phase3-serial"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        capture_module,
        "list_devices",
        lambda adb_path, timeout_seconds: result((str(adb_path), "devices", "-l"), f"List of devices attached\n{serial}\tdevice\n"),
    )

    class FakeClient:
        def __init__(self, adb_path: Path, serial: str, timeout_seconds: int) -> None:
            self.serial = serial

        def get_state(self) -> CommandResult:
            return result(("adb", "-s", self.serial, "get-state"), "device\n")

        def shell(self, arguments, timeout_seconds=None) -> CommandResult:
            arguments = tuple(arguments)
            calls.append(arguments)
            return result(("adb", "-s", self.serial, "shell", *arguments), "ok\n")

    monkeypatch.setattr(capture_module, "ADBClient", FakeClient)
    outcome = capture_evidence(
        Path("adb"),
        serial,
        tmp_path / "bundle",
        20,
        CaptureOptions(
            skip_display=True,
            skip_telephony=True,
            skip_packages=True,
            skip_magisk=True,
            skip_runtime_markers=True,
            skip_camera=True,
            skip_sensors=True,
            skip_hal=True,
        ),
    )
    manifest = load_evidence_bundle(outcome.bundle_path)

    assert manifest["schema_version"] == "3.0"
    assert all(state == "not_evaluated" for state in manifest["collector_states"].values())
    assert not any(call in {("dumpsys", "media.camera"), ("dumpsys", "sensorservice"), ("lshal",)} for call in calls)


def test_cli_exposes_phase3_capture_flags_and_redaction_keeps_standard_names() -> None:
    parser = build_parser()
    audit = parser.parse_args(
        [
            "audit",
            "--adb-path",
            "adb",
            "--skip-camera",
            "--skip-sensors",
            "--skip-hal",
        ]
    )
    redacted = redact_text(
        "Client ID: CAMERA-CLIENT-SECRET-0001 Bearer synthetic-token-value-12345 "
        "C:\\Users\\fixture-user /home/fixture-user /data/user/10/com.synthetic.app "
        "android.hardware.camera.provider Bosch Synthetic"
    )

    assert audit.skip_camera and audit.skip_sensors and audit.skip_hal
    assert "CAMERA-CLIENT-SECRET-0001" not in redacted
    assert "fixture-user" not in redacted
    assert "android.hardware.camera.provider" in redacted
    assert "Bosch Synthetic" in redacted
