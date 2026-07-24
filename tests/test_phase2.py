from __future__ import annotations

import json
from pathlib import Path

import pytest

import device_audit.bundle as bundle_module
import device_audit.capture as capture_module
from device_audit.analysis import analyze_bundle
from device_audit.bundle import BundleIntegrityError, load_evidence_bundle, write_evidence_bundle
from device_audit.capture import (
    DEFAULT_PACKAGES,
    CaptureOptions,
    capture_evidence,
    normalize_packages,
)
from device_audit.models import CommandResult, EvidenceCommand
from device_audit.parsers import (
    parse_display_info,
    parse_magisk_info,
    parse_package_info,
    parse_runtime_markers,
    parse_telephony_info,
)
from device_audit.profiles import ProfileValidationError, profile_from_mapping
from device_audit.redaction import redact_text
from device_audit.rules import evaluate_profile


FIXTURES = Path(__file__).parent / "fixtures"


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


def test_display_parser_handles_physical_override_modes_and_hdr() -> None:
    display = parse_display_info(
        fixture("vmos_phase2", "display_wm_size.txt"),
        fixture("vmos_phase2", "display_wm_density.txt"),
        fixture("vmos_phase2", "display_dumpsys.txt"),
        fixture("vmos_phase2", "window_displays.txt"),
    )

    assert display.physical_size == "1080x2400"
    assert display.override_size == "1080x2340"
    assert display.physical_density == 420
    assert display.override_density == 440
    assert (display.logical_width, display.logical_height) == (1080, 2340)
    assert display.refresh_rates == (60.0, 120.0)
    assert display.active_mode == "2"
    assert len(display.supported_modes) == 2
    assert display.hdr_types == ("HDR10", "HLG")
    assert display.wide_color_support is True
    assert display.display_count == 1


def test_display_parser_tolerates_alternate_and_truncated_android_formats() -> None:
    samsung = parse_display_info(
        fixture("samsung_phase2", "display_wm_size.txt"),
        fixture("samsung_phase2", "display_wm_density.txt"),
        fixture("samsung_phase2", "display_dumpsys.txt"),
        fixture("samsung_phase2", "window_displays.txt"),
    )
    truncated = parse_display_info(
        fixture("malformed_phase2", "display_wm_size.txt"),
        fixture("malformed_phase2", "display_wm_density.txt"),
        fixture("malformed_phase2", "display_dumpsys.txt"),
        "",
    )

    assert samsung.refresh_rates == (60.0, 120.0)
    assert samsung.wide_color_support is True
    assert (samsung.logical_width, samsung.logical_height) == (1080, 2340)
    assert truncated.physical_size is None
    assert truncated.supported_modes == ()


def test_telephony_parser_preserves_inventory_without_identifiers() -> None:
    properties = {
        key: value
        for key, value in (
            line[1:].split("]: [", 1)
            for line in fixture("vmos_phase2", "getprop.txt").splitlines()
            if "]: [" in line
        )
    }
    properties = {key: value.rstrip("]") for key, value in properties.items()}
    telephony = parse_telephony_info(
        properties,
        fixture("vmos_phase2", "telephony_registry.txt"),
        fixture("vmos_phase2", "subscriptions.txt"),
        fixture("vmos_phase2", "telecom.txt"),
    )

    assert telephony.phone_count == 2
    assert telephony.sim_states == ("READY",)
    assert telephony.network_types == ("NR_SA", "LTE")
    assert telephony.operator_alpha == ("Verizon",)
    assert telephony.operator_numeric == ("310012",)
    assert telephony.operator_country_iso == ("us",)
    assert telephony.roaming == (False,)
    assert telephony.subscription_count == 2
    assert telephony.baseband == "g5300g-260705-260710-B-14012001"
    assert telephony.ril_implementation == "Samsung S.LSI Vendor RIL"
    assert "imei" not in telephony.radio_properties


def test_telephony_parser_handles_missing_sim_permission_and_unicode() -> None:
    empty = parse_telephony_info(
        {"gsm.sim.state": "ABSENT", "gsm.network.type": "UNKNOWN"},
        fixture("aosp_emulator_phase2", "telephony_registry.txt"),
        fixture("aosp_emulator_phase2", "subscriptions.txt"),
        "",
    )
    denied = fixture("permission_denied_phase2", "telephony_registry.txt")

    assert empty.phone_count == 0
    assert empty.sim_states == ("ABSENT",)
    assert empty.subscription_count == 0
    assert "Permission Denial" in denied
    assert "Thiết bị" in fixture("malformed_phase2", "getprop.txt")


def test_package_parser_handles_split_paths_flags_and_absence() -> None:
    gms = parse_package_info(
        "com.google.android.gms",
        fixture("vmos_phase2", "package_paths_gms.txt"),
        fixture("vmos_phase2", "package_com_google_android_gms.txt"),
    )
    absent = parse_package_info(
        "com.google.android.gms",
        "",
        fixture("aosp_emulator_phase2", "package_missing.txt"),
        path_stderr="Unknown package: com.google.android.gms",
    )

    assert gms.installed is True
    assert gms.version_name == "26.01.00"
    assert gms.version_code == 260100000
    assert gms.code_paths == (
        "/product/priv-app/PrebuiltGmsCore/PrebuiltGmsCore.apk",
        "/product/priv-app/PrebuiltGmsCore/split_config.arm64_v8a.apk",
    )
    assert gms.enabled is True
    assert gms.system_app is True
    assert gms.privileged_app is True
    assert gms.signing_certificate_digests == ("AABBCCDDEEFF00112233445566778899",)
    assert absent.installed is False


def test_package_parser_tolerates_malformed_dump_without_resolver_summary() -> None:
    package = parse_package_info(
        "com.example.valid",
        "",
        fixture("malformed_phase2", "package.txt"),
    )

    assert package.installed is None
    assert package.version_code is None
    assert "Intent Resolver Table" not in json.dumps(package.__dict__)


@pytest.mark.parametrize("value", ["android", "com.example", "com.example_123.app", "x.y"])
def test_package_normalization_deduplicates_default_packages(value: str) -> None:
    packages = normalize_packages((value, value))

    assert packages == tuple(dict.fromkeys((*DEFAULT_PACKAGES, value)))


@pytest.mark.parametrize("value", ["", "single", "com.example;id", "com.example $(id)", "com..example"])
def test_package_normalization_rejects_unsafe_names(value: str) -> None:
    with pytest.raises(ValueError, match="package"):
        normalize_packages((value,))


def test_magisk_and_runtime_parsers_remain_inventory_only() -> None:
    magisk = parse_magisk_info(
        "/system/xbin/su\n",
        fixture("vmos_phase2", "root_id.txt"),
        fixture("vmos_phase2", "magisk_version.txt"),
        fixture("vmos_phase2", "magisk_version_code.txt"),
        fixture("vmos_phase2", "magisk_path.txt"),
        fixture("vmos_phase2", "magisk_settings.txt"),
        fixture("vmos_phase2", "magisk_modules.txt"),
        "true\n",
    )
    runtime = parse_runtime_markers(
        fixture("vmos_phase2", "mount.txt"),
        "",
        fixture("vmos_phase2", "processes.txt"),
        fixture("vmos_phase2", "services.txt"),
        "drwxr-xr-x root root /debug_ramdisk\n",
        fixture("vmos_phase2", "data_adb.txt"),
        "drwxr-xr-x root root /data/adb/modules\n",
        "drwxr-xr-x root root /data/adb/magisk\n",
    )

    assert magisk.root_available is True
    assert magisk.root_uid == 0
    assert magisk.magisk_installed is True
    assert magisk.magisk_version == "28.1:MAGISK"
    assert magisk.magisk_version_code == 28100
    assert magisk.zygisk_setting == "1"
    assert magisk.denylist_setting == "0"
    assert magisk.module_names == ("playintegrityfix", "systemless_hosts")
    assert runtime.markers == (
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
            "vmos",
    )


def test_magisk_parser_tolerates_root_unavailable_and_sqlite_failure() -> None:
    missing = parse_magisk_info("", "su: not found", "", "", "", "Permission denied", "", "")

    assert missing.root_available is False
    assert missing.magisk_installed is False
    assert missing.zygisk_setting is None


def test_explicit_phase2_profile_expectations_drive_findings_only_when_declared() -> None:
    display = parse_display_info(
        fixture("pixel_phase2", "display_wm_size.txt"),
        fixture("pixel_phase2", "display_wm_density.txt"),
        fixture("pixel_phase2", "display_dumpsys.txt"),
        fixture("pixel_phase2", "window_displays.txt"),
    )
    telephony = parse_telephony_info(
        {
            "gsm.network.type": "NR_SA",
            "gsm.operator.numeric": "310012",
            "gsm.operator.iso-country": "us",
            "gsm.version.baseband": "g5300g-260705-260710-B-14012001",
            "ro.telephony.ril_impl": "Samsung S.LSI Vendor RIL",
        },
        fixture("pixel_phase2", "telephony_registry.txt"),
        fixture("pixel_phase2", "subscriptions.txt"),
        "",
    )
    gms = parse_package_info(
        "com.google.android.gms",
        fixture("pixel_phase2", "package_paths_gms.txt"),
        fixture("pixel_phase2", "package_com_google_android_gms.txt"),
    )
    inventory_profile = profile_from_mapping({"schema_version": "1.0", "name": "Inventory"})
    matched_profile = profile_from_mapping(
        {
            "schema_version": "1.0",
            "name": "Reference",
            "display": {
                "allowed_physical_sizes": ["1344x2992"],
                "allowed_density_ranges": [{"min": 450, "max": 520}],
                "allowed_refresh_rates": [60.0, 120.0],
            },
            "telephony": {
                "allowed_operator_numeric": ["310012"],
                "allowed_country_iso": ["us"],
                "allowed_network_types": ["NR_SA", "LTE"],
                "allowed_ril_vendors": ["Samsung S.LSI Vendor RIL"],
                "allowed_baseband_patterns": ["^g5300g-"],
            },
            "packages": {
                "com.google.android.gms": {
                    "required": True,
                    "allowed_version_code_ranges": [{"min": 250000000, "max": 999999999}],
                    "required_enabled": True,
                    "required_not_suspended": True,
                }
            },
        }
    )
    mismatch_profile = profile_from_mapping(
        {
            "schema_version": "1.0",
            "name": "Mismatch",
            "display": {"allowed_physical_sizes": ["1080x2400"]},
            "telephony": {"allowed_operator_numeric": ["999999"]},
            "packages": {
                "com.google.android.gms": {
                    "required": True,
                    "allowed_version_code_ranges": [{"min": 1, "max": 2}],
                }
            },
        }
    )

    assert evaluate_profile({}, None, None, inventory_profile, display, telephony, {gms.package_name: gms}) == []
    assert evaluate_profile({}, None, None, matched_profile, display, telephony, {gms.package_name: gms}) == []
    assert {finding.category for finding in evaluate_profile({}, None, None, mismatch_profile, display, telephony, {gms.package_name: gms})} == {
        "display",
        "packages",
        "telephony",
    }


def test_profile_validation_rejects_invalid_phase2_expectations() -> None:
    with pytest.raises(ProfileValidationError, match="display.allowed_density_ranges"):
        profile_from_mapping(
            {
                "schema_version": "1.0",
                "name": "Invalid",
                "display": {"allowed_density_ranges": [{"min": 600, "max": 500}]},
            }
        )
    with pytest.raises(ProfileValidationError, match="packages"):
        profile_from_mapping(
            {
                "schema_version": "1.0",
                "name": "Invalid",
                "packages": {"not a package": {"required": True}},
            }
        )


def test_phase2_bundle_replay_reports_sections_and_redacts_every_artifact(tmp_path) -> None:
    serial = "fixture-device:5555"
    bundle = write_phase2_bundle(tmp_path / f"audit_{serial}", serial)
    report_output = tmp_path / "report"
    outcome = analyze_bundle(bundle, report_output)
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))
    replay = analyze_bundle(bundle, tmp_path / "replay")

    assert report["bundle_schema_version"] == "2.0"
    assert report["sections"]["display"]["status"] == "observed"
    assert report["sections"]["telephony"]["status"] == "observed"
    assert report["sections"]["packages"]["status"] == "observed"
    assert report["sections"]["google_play_services"]["status"] == "observed"
    assert report["sections"]["magisk"]["status"] == "observed"
    assert report["sections"]["runtime_markers"]["status"] == "observed"
    assert outcome.findings == replay.findings
    assert "Google Play Services" in (report_output / "report.md").read_text(encoding="utf-8")
    assert serial not in str(bundle)

    secrets = (serial, "TEST-IMEI-0001", "TEST-SUBSCRIBER-0001", "TEST-PHONE-0001")
    for artifact in [
        bundle / "evidence.json",
        bundle / "commands.jsonl",
        bundle / "audit.log",
        *sorted((bundle / "raw").glob("*.txt")),
        report_output / "report.json",
        report_output / "report.md",
    ]:
        contents = artifact.read_text(encoding="utf-8")
        assert not any(secret in contents for secret in secrets)


def test_phase2_bundle_supports_skipped_optional_collectors_and_schema_one_replay(tmp_path) -> None:
    bundle = write_evidence_bundle(
        tmp_path / "v1_bundle",
        serial="fixture-serial",
        commands=[
            EvidenceCommand(
                id="properties.getprop",
                section="properties",
                result=result(("adb", "-s", "fixture-serial", "shell", "getprop"), "[ro.product.model]: [A]\n"),
            )
        ],
        schema_version="1.0",
    )
    manifest = load_evidence_bundle(bundle)
    analyze_bundle(bundle, tmp_path / "v1_report")

    assert manifest["schema_version"] == "1.0"
    assert (tmp_path / "v1_report" / "report.json").exists()
    assert CaptureOptions(skip_display=True, skip_packages=True).skip_display is True


def test_phase2_bundle_rejects_digest_tampering_and_redacts_uuid_phone_context() -> None:
    subscriber_id = "TEST-SUBSCRIBER-0001"
    android_id = "550e8400" + "-e29b-41d4-a716-446655440000"
    phone = "+1 " + "(202)" + " 555-" + "0100"
    text = f"subscriberId={subscriber_id} android_id: {android_id} phone: {phone}"
    redacted = redact_text(text)

    assert subscriber_id not in redacted
    assert android_id not in redacted
    assert phone not in redacted


def test_phase2_bundle_digest_tampering_is_rejected(tmp_path) -> None:
    bundle = write_phase2_bundle(tmp_path / "bundle", "fixture-serial")
    evidence_path = bundle / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["collector_states"]["display"] = "tampered"
    evidence["bundle_digest"] = bundle_module._manifest_digest(evidence)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(BundleIntegrityError, match="collector_states"):
        load_evidence_bundle(bundle)


def test_bundle_rejects_digest_valid_unredacted_target_metadata(tmp_path) -> None:
    bundle = write_phase2_bundle(tmp_path / "bundle", "fixture-serial")
    evidence_path = bundle / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["target"]["serial"] = "fixture-serial"
    evidence["bundle_digest"] = bundle_module._manifest_digest(evidence)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(BundleIntegrityError, match="target metadata"):
        load_evidence_bundle(bundle)


def test_redaction_covers_m_prefixed_telephony_labels() -> None:
    redacted = redact_text(
        "mImei=TEST-IMEI-0001 mSubscriberId=TEST-SUBSCRIBER-0001 mIccId=TEST-ICCID-0001"
    )

    assert "TEST-IMEI-0001" not in redacted
    assert "TEST-SUBSCRIBER-0001" not in redacted
    assert "TEST-ICCID-0001" not in redacted


def test_capture_rejects_unsafe_package_before_contacting_adb(monkeypatch, tmp_path) -> None:
    contacted = False

    def fake_list_devices(*args, **kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("ADB must not be contacted for invalid package input")

    monkeypatch.setattr(capture_module, "list_devices", fake_list_devices)

    with pytest.raises(ValueError, match="package"):
        capture_evidence(
            Path("adb.exe"),
            "device",
            tmp_path / "bundle",
            20,
            CaptureOptions(packages=("com.example;id",)),
        )

    assert contacted is False


def test_capture_skip_flags_omit_all_phase2_commands(monkeypatch, tmp_path) -> None:
    calls: list[tuple[str, ...]] = []
    serial = "fixture-serial"
    _install_fake_adb(monkeypatch, calls, serial, root_available=True)

    bundle = capture_evidence(
        Path("adb.exe"),
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
            skip_audio=True,
            skip_battery=True,
            skip_thermal=True,
            skip_storage=True,
        ),
    ).bundle_path
    manifest = load_evidence_bundle(bundle)

    assert not any(call[0] in {"wm", "dumpsys", "cmd", "command", "su", "mount", "ps", "service", "ls"} for call in calls)
    assert all(state == "not_evaluated" for state in manifest["collector_states"].values())


def test_capture_root_gate_uses_only_bounded_read_only_commands(monkeypatch, tmp_path) -> None:
    calls: list[tuple[str, ...]] = []
    serial = "fixture-serial"
    _install_fake_adb(monkeypatch, calls, serial, root_available=True)

    outcome = capture_evidence(
        Path("adb.exe"),
        serial,
        tmp_path / "bundle",
        20,
        CaptureOptions(),
    )
    manifest = load_evidence_bundle(outcome.bundle_path)
    root_index = calls.index(("su", "-c", "id"))
    privileged = [call for call in calls if call[:2] == ("su", "-c") and call != ("su", "-c", "id")]

    assert all(calls.index(call) > root_index for call in privileged)
    assert all(
        entry["command"][1:3] == ["-s", "<redacted-serial>"]
        for entry in manifest["commands"]
        if entry["id"] != "transport.devices"
    )
    allowed_root_scripts = {
        "magisk -v 2>/dev/null",
        "magisk -V 2>/dev/null",
        "magisk --path 2>/dev/null",
        'magisk --sqlite "select key,value from settings;" 2>/dev/null',
        "ls -1 /data/adb/modules 2>/dev/null",
        "ls -la /data/adb 2>/dev/null",
        "ls -la /data/adb/modules 2>/dev/null",
        "ls -la /data/adb/magisk 2>/dev/null",
    }
    assert {call[2] for call in privileged} <= allowed_root_scripts
    joined = "\n".join(" ".join(call) for call in calls).lower()
    for forbidden in ("setprop", "resetprop", "pm install", "pm uninstall", "clear data", "chmod", "chown", "rm -", "find /data/adb"):
        assert forbidden not in joined


def test_package_absence_is_observed_not_a_collector_failure(monkeypatch, tmp_path) -> None:
    calls: list[tuple[str, ...]] = []
    serial = "fixture-serial"
    _install_fake_adb(monkeypatch, calls, serial, root_available=False, packages_absent=True)

    outcome = capture_evidence(
        Path("adb.exe"),
        serial,
        tmp_path / "bundle",
        20,
        CaptureOptions(
            skip_display=True,
            skip_telephony=True,
            skip_magisk=True,
            skip_runtime_markers=True,
        ),
    )
    manifest = load_evidence_bundle(outcome.bundle_path)

    assert outcome.collector_errors == 0
    assert all(
        entry["status"] == "observed"
        for entry in manifest["commands"]
        if entry["section"] == "packages"
    )


def test_phase2_permission_and_timeout_states_do_not_create_findings(tmp_path) -> None:
    serial = "fixture-serial"
    root = ("adb", "-s", serial, "shell")
    bundle = write_evidence_bundle(
        tmp_path / "bundle",
        serial=serial,
        commands=[
            EvidenceCommand(
                "display.dumpsys",
                "display",
                result((*root, "dumpsys", "display"), exit_code=None, timed_out=True),
            ),
            EvidenceCommand(
                "telephony.registry",
                "telephony",
                result(
                    (*root, "dumpsys", "telephony.registry"),
                    stderr="Permission Denial",
                    exit_code=1,
                ),
            ),
        ],
        collector_states={
            "display": "timeout",
            "telephony": "permission_denied",
            "packages": "not_evaluated",
            "magisk": "not_evaluated",
            "runtime_markers": "not_evaluated",
        },
    )
    outcome = analyze_bundle(bundle, tmp_path / "report")
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))

    assert outcome.findings == ()
    assert report["sections"]["display"]["status"] == "timeout"
    assert report["sections"]["telephony"]["status"] == "permission_denied"
    assert report["sections"]["telephony"]["permission_limits"] == ["telephony.registry"]


def _install_fake_adb(
    monkeypatch,
    calls: list[tuple[str, ...]],
    serial: str,
    *,
    root_available: bool,
    packages_absent: bool = False,
) -> None:
    monkeypatch.setattr(
        capture_module,
        "list_devices",
        lambda adb_path, timeout_seconds: result(
            (str(adb_path), "devices", "-l"),
            f"List of devices attached\n{serial}\tdevice\n",
        ),
    )

    class FakeClient:
        def __init__(self, adb_path: Path, serial: str, timeout_seconds: int) -> None:
            self.adb_path = adb_path
            self.serial = serial

        def get_state(self) -> CommandResult:
            return result((str(self.adb_path), "-s", self.serial, "get-state"), "device\n")

        def shell(self, arguments, timeout_seconds=None) -> CommandResult:
            arguments_tuple = tuple(arguments)
            calls.append(arguments_tuple)
            command = (str(self.adb_path), "-s", self.serial, "shell", *arguments_tuple)
            if arguments_tuple == ("command", "-v", "su"):
                return result(command, "/system/xbin/su\n" if root_available else "")
            if arguments_tuple == ("su", "-c", "id"):
                return result(command, "uid=0(root) context=u:r:magisk:s0\n")
            if arguments_tuple == ("su", "-c", "magisk -v 2>/dev/null"):
                return result(command, "28.1\n")
            if arguments_tuple[:3] == ("cmd", "package", "path"):
                package_name = arguments_tuple[-1]
                if packages_absent:
                    return result(command, exit_code=1)
                return result(command, f"package:/system/{package_name}.apk\n")
            if arguments_tuple[:2] == ("dumpsys", "package"):
                package_name = arguments_tuple[-1]
                if packages_absent:
                    return result(command, f"Unable to find package: {package_name}", exit_code=1)
                return result(command, f"Package [{package_name}]\nversionCode=1 enabled=true\n")
            return result(command, "ok\n")

    monkeypatch.setattr(capture_module, "ADBClient", FakeClient)


def write_phase2_bundle(output_dir: Path, serial: str) -> Path:
    root = ("adb", "-s", serial, "shell")
    commands = [
        EvidenceCommand("properties.getprop", "properties", result((*root, "getprop"), fixture("vmos_phase2", "getprop.txt"))),
        EvidenceCommand("display.wm_size", "display", result((*root, "wm", "size"), fixture("vmos_phase2", "display_wm_size.txt"))),
        EvidenceCommand("display.wm_density", "display", result((*root, "wm", "density"), fixture("vmos_phase2", "display_wm_density.txt"))),
        EvidenceCommand("display.dumpsys", "display", result((*root, "dumpsys", "display"), fixture("vmos_phase2", "display_dumpsys.txt"))),
        EvidenceCommand("display.window_displays", "display", result((*root, "dumpsys", "window", "displays"), fixture("vmos_phase2", "window_displays.txt"))),
        EvidenceCommand("display.forced_density", "display", result((*root, "settings", "get", "system", "display_density_forced"), "440\n")),
        EvidenceCommand("telephony.registry", "telephony", result((*root, "dumpsys", "telephony.registry"), fixture("vmos_phase2", "telephony_registry.txt"))),
        EvidenceCommand("telephony.isub", "telephony", result((*root, "dumpsys", "isub"), fixture("vmos_phase2", "subscriptions.txt"))),
        EvidenceCommand("telephony.telecom", "telephony", result((*root, "dumpsys", "telecom"), fixture("vmos_phase2", "telecom.txt"))),
        EvidenceCommand("packages.com_google_android_gms.path", "packages", result((*root, "cmd", "package", "path", "com.google.android.gms"), fixture("vmos_phase2", "package_paths_gms.txt"))),
        EvidenceCommand("packages.com_google_android_gms.dumpsys", "packages", result((*root, "dumpsys", "package", "com.google.android.gms"), fixture("vmos_phase2", "package_com_google_android_gms.txt"))),
        EvidenceCommand("root.su_path", "magisk", result((*root, "command", "-v", "su"), "/system/xbin/su\n")),
        EvidenceCommand("root.id", "magisk", result((*root, "su", "-c", "id"), fixture("vmos_phase2", "root_id.txt"))),
        EvidenceCommand("magisk.version", "magisk", result((*root, "su", "-c", "magisk -v 2>/dev/null"), fixture("vmos_phase2", "magisk_version.txt"))),
        EvidenceCommand("magisk.version_code", "magisk", result((*root, "su", "-c", "magisk -V 2>/dev/null"), fixture("vmos_phase2", "magisk_version_code.txt"))),
        EvidenceCommand("magisk.path", "magisk", result((*root, "su", "-c", "magisk --path 2>/dev/null"), fixture("vmos_phase2", "magisk_path.txt"))),
        EvidenceCommand("magisk.settings", "magisk", result((*root, "su", "-c", "magisk --sqlite \"select key,value from settings;\" 2>/dev/null"), fixture("vmos_phase2", "magisk_settings.txt"))),
        EvidenceCommand("magisk.modules", "magisk", result((*root, "su", "-c", "ls -1 /data/adb/modules 2>/dev/null"), fixture("vmos_phase2", "magisk_modules.txt"))),
        EvidenceCommand("magisk.cloud_property", "magisk", result((*root, "getprop", "ro.sys.cloud.magisk"), "true\n")),
        EvidenceCommand("runtime.mount", "runtime_markers", result((*root, "mount"), fixture("vmos_phase2", "mount.txt"))),
        EvidenceCommand("runtime.proc_mounts", "runtime_markers", result((*root, "cat", "/proc/mounts"), fixture("vmos_phase2", "mount.txt"))),
        EvidenceCommand("runtime.processes", "runtime_markers", result((*root, "ps", "-A"), fixture("vmos_phase2", "processes.txt"))),
        EvidenceCommand("runtime.services", "runtime_markers", result((*root, "service", "list"), fixture("vmos_phase2", "services.txt"))),
        EvidenceCommand("runtime.debug_ramdisk", "runtime_markers", result((*root, "ls", "-la", "/debug_ramdisk"), "drwxr-xr-x root root /debug_ramdisk\n")),
        EvidenceCommand("runtime.data_adb", "runtime_markers", result((*root, "su", "-c", "ls -la /data/adb 2>/dev/null"), fixture("vmos_phase2", "data_adb.txt"))),
        EvidenceCommand("runtime.data_adb_modules", "runtime_markers", result((*root, "su", "-c", "ls -la /data/adb/modules 2>/dev/null"), "drwxr-xr-x root root /data/adb/modules\n")),
        EvidenceCommand("runtime.data_adb_magisk", "runtime_markers", result((*root, "su", "-c", "ls -la /data/adb/magisk 2>/dev/null"), "drwxr-xr-x root root /data/adb/magisk\n")),
    ]
    return write_evidence_bundle(
        output_dir,
        serial=serial,
        commands=commands,
        collector_states={
            "display": "observed",
            "telephony": "observed",
            "packages": "observed",
            "magisk": "observed",
            "runtime_markers": "observed",
        },
    )
