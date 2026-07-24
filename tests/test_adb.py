from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from device_audit.adb import (
    ADBClient,
    ADBNotFoundError,
    DeviceSelectionError,
    choose_serial,
    parse_devices,
)


def test_parse_devices_preserves_state_and_serial() -> None:
    devices = parse_devices(
        """
List of devices attached
emulator-5554\tdevice product:sdk_gphone model:sdk_gphone_x86 device:generic_x86
fixture-device:5555\tunauthorized usb:1-2
""".strip()
    )

    assert devices[0].serial == "emulator-5554"
    assert devices[0].state == "device"
    assert devices[1].state == "unauthorized"


def test_choose_serial_requires_one_ready_device_when_unspecified() -> None:
    with pytest.raises(DeviceSelectionError, match="more than one"):
        choose_serial(
            parse_devices(
                "List of devices attached\na\tdevice\nb\tdevice\n"
            ),
            requested_serial=None,
        )


def test_choose_serial_reports_unauthorized_target() -> None:
    with pytest.raises(DeviceSelectionError, match="unauthorized"):
        choose_serial(
            parse_devices("List of devices attached\nphone\tunauthorized\n"),
            requested_serial=None,
        )


def test_adb_client_uses_argument_list_for_paths_with_spaces(monkeypatch) -> None:
    calls: list[dict] = []

    def fake_run(args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        return subprocess.CompletedProcess(args, 0, b"value\n", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    adb_path = Path("fixture root") / "Program Files" / "Android SDK" / "platform-tools" / "adb.exe"
    serial = "fixture-device:5555"
    client = ADBClient(adb_path=adb_path, serial=serial, timeout_seconds=7)

    result = client.shell(["getprop", "ro.product.model"])

    assert result.exit_code == 0
    assert calls[0]["args"] == [
        str(adb_path),
        "-s",
        serial,
        "shell",
        "getprop",
        "ro.product.model",
    ]
    assert calls[0]["kwargs"]["shell"] is False
    assert calls[0]["kwargs"]["timeout"] == 7


def test_adb_client_maps_missing_executable() -> None:
    client = ADBClient(adb_path=Path("missing-adb.exe"), serial="device")

    with pytest.raises(ADBNotFoundError):
        client.get_state()


def test_adb_client_records_timeout_without_crashing(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    client = ADBClient(adb_path=Path("adb.exe"), serial="device", timeout_seconds=3)

    result = client.shell(["getprop"])

    assert result.timed_out is True
    assert result.exit_code is None
