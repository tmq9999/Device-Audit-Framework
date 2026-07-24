from __future__ import annotations

import json
from pathlib import Path

from device_audit import capture as capture_module
from device_audit.analysis import AnalysisOutcome
from device_audit.capture import CaptureOutcome, capture_evidence
from device_audit.cli import main
from device_audit.models import CommandResult


def result(
    command: tuple[str, ...],
    stdout: str = "",
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
        duration_ms=5,
        timed_out=timed_out,
    )


def test_capture_continues_after_one_collector_error_and_redacts_all_serials(monkeypatch, tmp_path) -> None:
    target_serial = "target-serial-123"
    other_serial = "other-serial-456"
    calls: list[tuple[str, ...]] = []

    monkeypatch.setattr(
        capture_module,
        "list_devices",
        lambda adb_path, timeout_seconds: result(
            (str(adb_path), "devices", "-l"),
            f"List of devices attached\n{target_serial}\tdevice\n{other_serial}\toffline\n",
        ),
    )

    class FakeClient:
        def __init__(self, adb_path: Path, serial: str, timeout_seconds: int) -> None:
            assert serial == target_serial

        def get_state(self) -> CommandResult:
            return result(("adb", "-s", target_serial, "get-state"), "device\n")

        def shell(self, arguments, timeout_seconds=None) -> CommandResult:
            arguments_tuple = tuple(arguments)
            calls.append(arguments_tuple)
            command = ("adb", "-s", target_serial, "shell", *arguments_tuple)
            if arguments_tuple == ("getprop",):
                return result(command, exit_code=1, stderr="permission denied")
            if arguments_tuple == ("uname", "-a"):
                return result(command, "Linux host 5.10.107-android13-4 aarch64\n")
            if arguments_tuple == ("cat", "/proc/cpuinfo"):
                return result(command, "processor : 0\nCPU implementer : 0x41\nCPU part : 0xd05\n")
            if arguments_tuple == ("getconf", "_NPROCESSORS_ONLN"):
                return result(command, "1\n")
            return result(command, "ok\n")

    monkeypatch.setattr(capture_module, "ADBClient", FakeClient)

    outcome = capture_evidence(
        adb_path=Path("adb.exe"),
        requested_serial=target_serial,
        output_dir=tmp_path / "bundle",
        timeout_seconds=20,
    )

    manifest_text = (outcome.bundle_path / "evidence.json").read_text(encoding="utf-8")
    devices_raw = (outcome.bundle_path / "raw" / "transport_devices.stdout.txt").read_text(
        encoding="utf-8"
    )
    assert outcome.collector_errors == 1
    assert ("cat", "/proc/cpuinfo") in calls
    assert target_serial not in manifest_text + devices_raw
    assert other_serial not in manifest_text + devices_raw


def test_default_cli_invocation_runs_composed_audit(monkeypatch, tmp_path) -> None:
    bundle_path = tmp_path / "audit"
    calls: list[str] = []

    def fake_capture(**kwargs) -> CaptureOutcome:
        calls.append("capture")
        bundle_path.mkdir()
        return CaptureOutcome(bundle_path=bundle_path, collector_errors=0)

    def fake_analyze(bundle_dir, output_dir, profile_path=None) -> AnalysisOutcome:
        calls.append("analyze")
        report_path = output_dir / "report.json"
        report_path.write_text("{}", encoding="utf-8")
        return AnalysisOutcome(findings=(), collector_errors=0, report_path=report_path)

    monkeypatch.setattr("device_audit.cli.capture_evidence", fake_capture)
    monkeypatch.setattr("device_audit.cli.analyze_bundle", fake_analyze)

    exit_code = main(
        [
            "--adb-path",
            "adb.exe",
            "--serial",
            "device",
            "--output-dir",
            str(bundle_path),
        ]
    )

    assert exit_code == 0
    assert calls == ["capture", "analyze"]


def test_analyze_cli_returns_one_for_recorded_collector_errors(monkeypatch, tmp_path) -> None:
    report_path = tmp_path / "analysis" / "report.json"

    def fake_analyze(bundle_dir, output_dir, profile_path=None) -> AnalysisOutcome:
        output_dir.mkdir(parents=True)
        report_path.write_text(json.dumps({}), encoding="utf-8")
        return AnalysisOutcome(findings=(), collector_errors=2, report_path=report_path)

    monkeypatch.setattr("device_audit.cli.analyze_bundle", fake_analyze)

    exit_code = main(
        [
            "analyze",
            "--bundle",
            str(tmp_path / "bundle"),
            "--output-dir",
            str(tmp_path / "analysis"),
        ]
    )

    assert exit_code == 1
