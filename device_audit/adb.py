"""Safe, serial-explicit ADB process execution."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
import subprocess
import time

from device_audit.models import CommandResult, DeviceInfo


class AuditError(Exception):
    """Base exception for audit failures."""


class ADBNotFoundError(AuditError):
    """Raised when the configured ADB executable cannot be launched."""


class DeviceSelectionError(AuditError):
    """Raised when a ready target cannot be selected unambiguously."""


def parse_devices(text: str) -> list[DeviceInfo]:
    """Parse `adb devices -l` output."""

    devices: list[DeviceInfo] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("List of devices attached") or stripped.startswith("*"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        devices.append(DeviceInfo(serial=parts[0], state=parts[1], details=tuple(parts[2:])))
    return devices


def choose_serial(devices: Sequence[DeviceInfo], requested_serial: str | None) -> str:
    """Choose an explicit requested target or exactly one ready target."""

    if requested_serial:
        for device in devices:
            if device.serial == requested_serial:
                if device.state != "device":
                    raise DeviceSelectionError(
                        f"requested device {requested_serial!r} is {device.state}, not ready"
                    )
                return requested_serial
        raise DeviceSelectionError(f"requested device {requested_serial!r} was not found")

    ready = [device for device in devices if device.state == "device"]
    if len(ready) == 1:
        return ready[0].serial
    if len(ready) > 1:
        raise DeviceSelectionError("more than one ready device; pass --serial")
    if devices:
        states = ", ".join(sorted({device.state for device in devices}))
        raise DeviceSelectionError(f"no ready device; observed state(s): {states}")
    raise DeviceSelectionError("no devices reported by adb")


class ADBClient:
    """Run whitelisted ADB commands without host-shell interpolation."""

    def __init__(self, adb_path: Path, serial: str, timeout_seconds: int = 20) -> None:
        self.adb_path = Path(adb_path)
        self.serial = serial
        self.timeout_seconds = timeout_seconds

    def run_adb(self, arguments: Sequence[str], timeout_seconds: int | None = None) -> CommandResult:
        """Run an ADB command using an argument list and capture all output."""

        command = [str(self.adb_path), *arguments]
        timeout = timeout_seconds if timeout_seconds is not None else self.timeout_seconds
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                shell=False,
                timeout=timeout,
            )
        except FileNotFoundError as error:
            raise ADBNotFoundError(f"ADB executable not found: {self.adb_path}") from error
        except subprocess.TimeoutExpired as error:
            return CommandResult(
                command=tuple(command),
                exit_code=None,
                stdout=_decode_output(error.stdout),
                stderr=_decode_output(error.stderr),
                duration_ms=int((time.monotonic() - started) * 1000),
                timed_out=True,
            )
        return CommandResult(
            command=tuple(command),
            exit_code=completed.returncode,
            stdout=_decode_output(completed.stdout),
            stderr=_decode_output(completed.stderr),
            duration_ms=int((time.monotonic() - started) * 1000),
            timed_out=False,
        )

    def shell(self, arguments: Sequence[str], timeout_seconds: int | None = None) -> CommandResult:
        """Run a serial-explicit Android shell command without interpolation."""

        return self.run_adb(
            ["-s", self.serial, "shell", *arguments],
            timeout_seconds=timeout_seconds,
        )

    def get_state(self) -> CommandResult:
        """Return the serial-explicit `adb get-state` result."""

        return self.run_adb(["-s", self.serial, "get-state"])


def list_devices(adb_path: Path, timeout_seconds: int = 20) -> CommandResult:
    """Run the host-level device discovery command."""

    discovery_client = ADBClient(adb_path=adb_path, serial="", timeout_seconds=timeout_seconds)
    return discovery_client.run_adb(["devices", "-l"])


def _decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="replace")
