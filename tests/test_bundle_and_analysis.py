from __future__ import annotations

import json
from pathlib import Path

import pytest

from device_audit import __version__
from device_audit.analysis import analyze_bundle
from device_audit.bundle import BundleIntegrityError, write_evidence_bundle
from device_audit.models import CommandResult, EvidenceCommand


def make_result(
    command: tuple[str, ...],
    stdout: str,
    *,
    exit_code: int | None = 0,
    timed_out: bool = False,
    stderr: str = "",
) -> CommandResult:
    return CommandResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=12,
        timed_out=timed_out,
    )


def test_bundle_writes_only_redacted_artifacts_and_commands(tmp_path) -> None:
    serial = "TEST-SERIAL-0001"
    fixture_email = "fixture.user@" + "example.invalid"
    bundle_path = tmp_path / "bundle"
    write_evidence_bundle(
        bundle_path,
        serial=serial,
        commands=[
            EvidenceCommand(
                id="properties.getprop",
                section="properties",
                result=make_result(
                    ("adb", "-s", serial, "shell", "getprop"),
                        f"email: {fixture_email}\nIMEI: TEST-IMEI-0001\n",
                ),
            )
        ],
    )

    evidence = (bundle_path / "evidence.json").read_text(encoding="utf-8")
    raw = (bundle_path / "raw" / "properties_getprop.stdout.txt").read_text(encoding="utf-8")
    commands = (bundle_path / "commands.jsonl").read_text(encoding="utf-8")
    command_lines = commands.splitlines()

    for artifact in (evidence, raw, commands):
        assert serial not in artifact
        assert fixture_email not in artifact
    assert "TEST-IMEI-0001" not in artifact
    assert "<redacted-serial>" in evidence
    assert len(command_lines) == 1
    assert json.loads(command_lines[0])["id"] == "properties.getprop"


def test_bundle_loader_rejects_tampered_raw_artifact(tmp_path) -> None:
    bundle_path = tmp_path / "bundle"
    write_evidence_bundle(
        bundle_path,
        serial="device",
        commands=[
            EvidenceCommand(
                id="kernel.uname",
                section="kernel",
                result=make_result(("adb", "-s", "device", "shell", "uname", "-a"), "Linux host 6.1\n"),
            )
        ],
    )
    raw_path = bundle_path / "raw" / "kernel_uname.stdout.txt"
    raw_path.write_text("tampered", encoding="utf-8")

    with pytest.raises(BundleIntegrityError, match="digest"):
        analyze_bundle(bundle_path, tmp_path / "analysis")


def test_offline_analysis_generates_reports_without_profile_findings(tmp_path) -> None:
    bundle_path = write_phase_one_bundle(tmp_path / "bundle")
    output_path = tmp_path / "analysis"

    outcome = analyze_bundle(bundle_path, output_path)

    report = json.loads((output_path / "report.json").read_text(encoding="utf-8"))
    assert outcome.findings == ()
    assert report["analyzer_version"] == __version__
    assert report["source_bundle_digest"]
    assert report["findings"] == []
    assert report["sections"]["properties"]["status"] == "observed"
    assert (output_path / "report.md").exists()
    assert (output_path / "summary.txt").exists()


def test_analysis_uses_profile_references_and_keeps_collector_timeout_nonfatal(tmp_path) -> None:
    bundle_path = write_phase_one_bundle(tmp_path / "bundle", properties_timed_out=True)
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "name": "Reference",
                "identity": {"model": "Expected model"},
                "kernel": {"allowed_lineages": ["android14-6.1"]},
                "native_cpu": {
                    "allowed_topologies": [
                        {
                            "online_cpu_count": 2,
                            "clusters": [
                                {"implementer": "0x41", "part": "0xd44", "count": 2}
                            ],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    outcome = analyze_bundle(bundle_path, tmp_path / "analysis", profile_path)

    finding_ids = {finding.id for finding in outcome.findings}
    assert finding_ids == {"KERNEL_LINEAGE_MISMATCH", "CPU_TOPOLOGY_MISMATCH"}
    assert outcome.collector_errors == 1


def write_phase_one_bundle(bundle_path: Path, properties_timed_out: bool = False) -> Path:
    serial = "device-serial"
    property_result = make_result(
        ("adb", "-s", serial, "shell", "getprop"),
        "[ro.product.model]: [Observed model]\n",
        exit_code=None if properties_timed_out else 0,
        timed_out=properties_timed_out,
    )
    write_evidence_bundle(
        bundle_path,
        serial=serial,
        commands=[
            EvidenceCommand(id="properties.getprop", section="properties", result=property_result),
            EvidenceCommand(
                id="kernel.uname",
                section="kernel",
                result=make_result(
                    ("adb", "-s", serial, "shell", "uname", "-a"),
                    "Linux host 5.10.107-android13-4 aarch64\n",
                ),
            ),
            EvidenceCommand(
                id="cpu.cpuinfo",
                section="cpu",
                result=make_result(
                    ("adb", "-s", serial, "shell", "cat", "/proc/cpuinfo"),
                    """processor : 0
CPU implementer : 0x41
CPU part : 0xd05

processor : 1
CPU implementer : 0x41
CPU part : 0xd05
""",
                ),
            ),
            EvidenceCommand(
                id="cpu.online_count",
                section="cpu",
                result=make_result(
                    ("adb", "-s", serial, "shell", "getconf", "_NPROCESSORS_ONLN"),
                    "2\n",
                ),
            ),
        ],
    )
    return bundle_path
