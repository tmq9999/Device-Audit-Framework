from __future__ import annotations

import json
from pathlib import Path

import pytest

import device_audit.bundle as bundle_module
from device_audit.analysis import analyze_bundle
from device_audit.bundle import BundleIntegrityError, command_status, load_evidence_bundle, write_evidence_bundle
from device_audit.models import CommandResult, CpuCluster, CpuTopology, EvidenceCommand, KernelInfo
from device_audit.parsers import parse_cpuinfo, parse_getprop, parse_kernel_info, parse_online_cpu_count
from device_audit.profiles import load_profile, profile_from_mapping
from device_audit.rules import evaluate_profile

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
SAMPLE_PROFILE = Path(__file__).parents[1] / "profiles" / "pixel_10_pro_cp1a.json"


def fixture_text(name: str, file_name: str) -> str:
    return (FIXTURE_ROOT / name / file_name).read_text(encoding="utf-8")


def command_result(
    command: tuple[str, ...],
    stdout: str,
    *,
    exit_code: int | None = 0,
    stderr: str = "",
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


def test_vmos_fixture_parses_android13_kernel_and_eight_core_topology() -> None:
    kernel = parse_kernel_info(fixture_text("vmos_android13", "uname.txt"))
    topology = parse_cpuinfo(fixture_text("vmos_android13", "cpuinfo.txt"), online_cpu_count=8)

    assert kernel.lineage == "android13-5.10"
    assert kernel.architecture == "aarch64"
    assert topology.online_cpu_count == 8
    assert topology.clusters == (
        CpuCluster(implementer="0x41", part="0xd05", count=4),
        CpuCluster(implementer="0x41", part="0xd41", count=2),
        CpuCluster(implementer="0x41", part="0xd44", count=2),
    )


def test_matching_pixel_reference_profile_has_no_findings() -> None:
    profile = load_profile(SAMPLE_PROFILE)
    properties = parse_getprop(fixture_text("pixel_reference", "getprop.txt"))
    kernel = parse_kernel_info(fixture_text("pixel_reference", "uname.txt"))
    cpu = parse_cpuinfo(fixture_text("pixel_reference", "cpuinfo.txt"), online_cpu_count=2)

    assert evaluate_profile(properties, kernel, cpu, profile) == []


def test_absent_kernel_and_cpu_references_are_inventory_only() -> None:
    profile = profile_from_mapping(
        {
            "schema_version": "1.0",
            "name": "Identity-only",
            "identity": {"model": "Pixel 10 Pro"},
        }
    )
    findings = evaluate_profile(
        properties={"ro.product.model": "Pixel 10 Pro"},
        kernel=KernelInfo(release="5.10.107-android13", lineage="android13-5.10"),
        cpu=CpuTopology(
            online_cpu_count=8,
            clusters=(CpuCluster(implementer="0x41", part="0xd05", count=8),),
        ),
        profile=profile,
    )

    assert findings == []


def test_explicit_kernel_reference_can_create_kernel_mismatch() -> None:
    profile = profile_from_mapping(
        {
            "schema_version": "1.0",
            "name": "Kernel reference",
            "kernel": {"allowed_lineages": ["android14-6.1"]},
        }
    )

    findings = evaluate_profile(
        properties={},
        kernel=KernelInfo(release="5.10.107-android13", lineage="android13-5.10"),
        cpu=None,
        profile=profile,
    )

    assert [finding.id for finding in findings] == ["KERNEL_LINEAGE_MISMATCH"]


def test_explicit_native_cpu_reference_can_create_topology_mismatch() -> None:
    profile = profile_from_mapping(
        {
            "schema_version": "1.0",
            "name": "CPU reference",
            "native_cpu": {
                "allowed_topologies": [
                    {
                        "online_cpu_count": 8,
                        "clusters": [{"implementer": "0x41", "part": "0xd44", "count": 8}],
                    }
                ]
            },
        }
    )

    findings = evaluate_profile(
        properties={},
        kernel=None,
        cpu=CpuTopology(
            online_cpu_count=8,
            clusters=(CpuCluster(implementer="0x41", part="0xd05", count=8),),
        ),
        profile=profile,
    )

    assert [finding.id for finding in findings] == ["CPU_TOPOLOGY_MISMATCH"]


def test_truncated_blank_permission_and_timeout_inputs_are_nonfatal() -> None:
    assert parse_kernel_info(fixture_text("malformed", "uname.txt")).release is None
    assert parse_cpuinfo(fixture_text("malformed", "cpuinfo.txt")).clusters == ()
    assert parse_getprop(fixture_text("malformed", "proc_version.txt")) == {}
    assert parse_getprop("") == {}
    assert parse_cpuinfo("").clusters == ()
    assert command_status(command_result(("adb",), "", exit_code=1, stderr="Permission denied")) == "permission_denied"
    assert command_status(command_result(("adb",), "", exit_code=None, timed_out=True)) == "timeout"


def test_malformed_getprop_duplicate_unicode_and_crlf_are_defensive() -> None:
    properties = parse_getprop(fixture_text("malformed", "getprop.txt").replace("\n", "\r\n"))

    assert properties["good.key"] == "second"
    assert properties["unicode.key"] == "測試 ✅"
    assert "unterminated.key" not in properties


def test_unknown_arm_implementer_and_part_values_are_preserved() -> None:
    topology = parse_cpuinfo(fixture_text("aosp_emulator", "cpuinfo.txt"), online_cpu_count=1)

    assert topology.clusters == (CpuCluster(implementer="0x99", part="0xabc", count=1),)


def test_cpu_online_parser_handles_ranges_and_bad_text() -> None:
    assert parse_online_cpu_count(fixture_text("vmos_android13", "cpu_online.txt")) == 8
    assert parse_online_cpu_count("8\r\n") == 8
    assert parse_online_cpu_count(fixture_text("malformed", "cpu_online.txt")) is None


def test_cpuinfo_without_blank_record_separators_keeps_every_processor() -> None:
    topology = parse_cpuinfo(
        "processor : 0\nCPU implementer : 0x41\nCPU part : 0xd05\n"
        "processor : 1\nCPU implementer : 0x41\nCPU part : 0xd05\n",
        online_cpu_count=2,
    )

    assert topology.clusters == (CpuCluster(implementer="0x41", part="0xd05", count=2),)


def test_cpuinfo_with_blank_lines_between_individual_fields_keeps_each_record() -> None:
    topology = parse_cpuinfo(
        "processor : 0\n\nCPU implementer : 0x41\n\nCPU part : 0xd05\n\n"
        "processor : 1\n\nCPU implementer : 0x41\n\nCPU part : 0xd05\n",
        online_cpu_count=2,
    )

    assert topology.clusters == (CpuCluster(implementer="0x41", part="0xd05", count=2),)


def test_analysis_uses_osrelease_when_uname_is_truncated(tmp_path) -> None:
    serial = "fixture-serial"
    bundle = write_evidence_bundle(
        tmp_path / "capture",
        serial=serial,
        commands=[
            EvidenceCommand(
                id="kernel.uname",
                section="kernel",
                result=command_result(("adb", "-s", serial, "shell", "uname", "-a"), "Linux\n"),
            ),
            EvidenceCommand(
                id="kernel.osrelease",
                section="kernel",
                result=command_result(
                    ("adb", "-s", serial, "shell", "cat", "/proc/sys/kernel/osrelease"),
                    "5.10.107-android13-4\n",
                ),
            ),
        ],
    )

    outcome = analyze_bundle(bundle, tmp_path / "analysis")
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))

    assert report["sections"]["kernel"]["status"] == "observed"
    assert report["sections"]["kernel"]["data"]["release"] == "5.10.107-android13-4"
    assert report["sections"]["kernel"]["data"]["lineage"] == "android13-5.10"


def test_analysis_uses_cpu_online_range_when_getconf_is_unavailable(tmp_path) -> None:
    serial = "fixture-serial"
    bundle = write_evidence_bundle(
        tmp_path / "capture",
        serial=serial,
        commands=[
            EvidenceCommand(
                id="cpu.cpuinfo",
                section="cpu",
                result=command_result(
                    ("adb", "-s", serial, "shell", "cat", "/proc/cpuinfo"),
                    fixture_text("vmos_android13", "cpuinfo.txt"),
                ),
            ),
            EvidenceCommand(
                id="cpu.online_count",
                section="cpu",
                result=command_result(
                    ("adb", "-s", serial, "shell", "getconf", "_NPROCESSORS_ONLN"),
                    "",
                    exit_code=1,
                    stderr="permission denied",
                ),
            ),
            EvidenceCommand(
                id="cpu.online_range",
                section="cpu",
                result=command_result(
                    ("adb", "-s", serial, "shell", "cat", "/sys/devices/system/cpu/online"),
                    "0-7\n",
                ),
            ),
        ],
    )

    outcome = analyze_bundle(bundle, tmp_path / "analysis")
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))

    assert report["sections"]["cpu"]["data"]["online_cpu_count"] == 8


def test_report_includes_transport_data_and_command_states(tmp_path) -> None:
    serial = "fixture-serial"
    bundle = write_evidence_bundle(
        tmp_path / "capture",
        serial=serial,
        commands=[
            EvidenceCommand(
                id="transport.state",
                section="transport",
                result=command_result(("adb", "-s", serial, "get-state"), "device\n"),
            ),
            EvidenceCommand(
                id="transport.id",
                section="transport",
                result=command_result(("adb", "-s", serial, "shell", "id"), "uid=2000(shell)\n"),
            ),
            EvidenceCommand(
                id="transport.getenforce",
                section="transport",
                result=command_result(
                    ("adb", "-s", serial, "shell", "getenforce"),
                    fixture_text("pixel_reference", "selinux.txt").splitlines()[0] + "\n",
                ),
            ),
        ],
    )

    outcome = analyze_bundle(bundle, tmp_path / "analysis")
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))
    transport = report["sections"]["transport"]

    assert transport["status"] == "observed"
    assert transport["data"] == {
        "device_state": "device",
        "selinux_mode": "Enforcing",
        "shell_identity": "uid=2000(shell)",
    }
    assert transport["commands"]["transport.state"] == "observed"


def test_bundle_replay_is_semantically_equivalent_for_repeated_offline_analysis(tmp_path) -> None:
    bundle = write_phase1_bundle(tmp_path / "capture")
    first = analyze_bundle(bundle, tmp_path / "analysis_a", SAMPLE_PROFILE)
    second = analyze_bundle(bundle, tmp_path / "analysis_b", SAMPLE_PROFILE)
    first_report = json.loads(first.report_path.read_text(encoding="utf-8"))
    second_report = json.loads(second.report_path.read_text(encoding="utf-8"))

    for report in (first_report, second_report):
        report.pop("generated_at")
        assert "profile_match_percent" not in report["summary"]
        assert "cross_layer_consistency_percent" not in report["summary"]
    assert first_report == second_report


def test_matching_profile_comparisons_are_explicit_in_report(tmp_path) -> None:
    bundle = write_phase1_bundle(tmp_path / "capture")
    outcome = analyze_bundle(bundle, tmp_path / "analysis", SAMPLE_PROFILE)
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))

    comparison_states = {comparison["field"]: comparison["status"] for comparison in report["comparisons"]}
    assert comparison_states["identity.model"] == "matched"
    assert comparison_states["build.fingerprint"] == "matched"
    assert comparison_states["kernel.lineage"] == "not_evaluated"
    assert comparison_states["native_cpu.topology"] == "not_evaluated"


def test_bundle_schema_version_mismatch_is_rejected(tmp_path) -> None:
    bundle = write_phase1_bundle(tmp_path / "capture")
    evidence_path = bundle / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["schema_version"] = "99.0"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(BundleIntegrityError, match="unsupported evidence bundle schema"):
        load_evidence_bundle(bundle)


def test_redaction_covers_raw_report_markdown_logs_jsonl_and_metadata(tmp_path) -> None:
    serial = "SERIAL-SECRET-123"
    output_dir = tmp_path / f"audit_{serial}"
    bundle = write_evidence_bundle(
        output_dir,
        serial=serial,
        additional_sensitive_values=("OTHER-SERIAL-456",),
        commands=[
            EvidenceCommand(
                id="properties.getprop",
                section="properties",
                result=command_result(
                    ("adb", "-s", serial, "shell", "getprop"),
                    "[ro.boot.serialno]: [OTHER-SERIAL-456]\n"
                    "[persist.sys.imei]: [TEST-IMEI-0001]\n"
                    "[persist.sys.email]: [FIXTURE-EMAIL-0001]\n",
                ),
            )
        ],
    )
    analysis = analyze_bundle(bundle, tmp_path / "analysis")
    artifacts = [
        bundle / "evidence.json",
        bundle / "commands.jsonl",
        bundle / "audit.log",
        bundle / "raw" / "properties_getprop.stdout.txt",
        analysis.report_path,
        analysis.report_path.with_name("report.md"),
    ]

    assert serial not in str(bundle)
    for artifact in artifacts:
        contents = artifact.read_text(encoding="utf-8")
        assert serial not in contents
        assert "OTHER-SERIAL-456" not in contents
        assert "TEST-IMEI-0001" not in contents
        assert "FIXTURE-EMAIL-0001" not in contents


def test_bundle_command_and_log_files_are_required_and_tamper_detected(tmp_path) -> None:
    bundle = write_phase1_bundle(tmp_path / "capture")
    (bundle / "commands.jsonl").unlink()

    with pytest.raises(BundleIntegrityError, match="commands.jsonl"):
        load_evidence_bundle(bundle)


def test_crlf_command_output_is_canonicalized_before_hashing_and_writing(tmp_path) -> None:
    bundle = write_evidence_bundle(
        tmp_path / "capture",
        serial="fixture-serial",
        commands=[
            EvidenceCommand(
                id="transport.devices",
                section="transport",
                result=command_result(
                    ("adb", "devices", "-l"),
                    "List of devices attached\r\nfixture-serial\tdevice\r\n\r\n",
                ),
            )
        ],
    )

    load_evidence_bundle(bundle)
    raw_bytes = (bundle / "raw" / "transport_devices.stdout.txt").read_bytes()
    assert b"\r\r\n" not in raw_bytes
    assert b"\r\n" not in raw_bytes


def test_coherent_malformed_command_metadata_raises_bundle_error(tmp_path) -> None:
    bundle = write_phase1_bundle(tmp_path / "capture")
    evidence_path = bundle / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["commands"][0] = "not-an-object"
    evidence["bundle_digest"] = bundle_module._manifest_digest(evidence)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(BundleIntegrityError, match="command entry"):
        load_evidence_bundle(bundle)


def write_phase1_bundle(bundle_path: Path) -> Path:
    serial = "fixture-serial"
    write_evidence_bundle(
        bundle_path,
        serial=serial,
        commands=[
            EvidenceCommand(
                id="properties.getprop",
                section="properties",
                result=command_result(
                    ("adb", "-s", serial, "shell", "getprop"),
                    fixture_text("pixel_reference", "getprop.txt"),
                ),
            ),
            EvidenceCommand(
                id="kernel.uname",
                section="kernel",
                result=command_result(
                    ("adb", "-s", serial, "shell", "uname", "-a"),
                    fixture_text("pixel_reference", "uname.txt"),
                ),
            ),
            EvidenceCommand(
                id="kernel.osrelease",
                section="kernel",
                result=command_result(
                    ("adb", "-s", serial, "shell", "cat", "/proc/sys/kernel/osrelease"),
                    "6.1.0-generic\n",
                ),
            ),
            EvidenceCommand(
                id="cpu.cpuinfo",
                section="cpu",
                result=command_result(
                    ("adb", "-s", serial, "shell", "cat", "/proc/cpuinfo"),
                    fixture_text("pixel_reference", "cpuinfo.txt"),
                ),
            ),
            EvidenceCommand(
                id="cpu.online_count",
                section="cpu",
                result=command_result(
                    ("adb", "-s", serial, "shell", "getconf", "_NPROCESSORS_ONLN"),
                    "2\n",
                ),
            ),
        ],
    )
    return bundle_path
