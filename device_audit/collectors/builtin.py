"""The frozen Phase 1/2 set plus Phase 3 hardware inventory for v0.10.0rc1."""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import cast

from device_audit.bundle import command_status
from device_audit.collector_api import (
    CollectionRequest,
    Collector,
    CollectorContext,
    CollectorResult,
    CommandSpec,
)
from device_audit.models import EvidenceCommand


PHASE_ONE_COMMANDS = (
    CommandSpec("transport.id", "transport", ("id",), 10),
    CommandSpec("transport.getenforce", "transport", ("getenforce",), 10),
    CommandSpec("properties.getprop", "properties", ("getprop",), 15),
    CommandSpec("kernel.uname", "kernel", ("uname", "-a"), 10),
    CommandSpec("kernel.proc_version", "kernel", ("cat", "/proc/version"), 10),
    CommandSpec("kernel.osrelease", "kernel", ("cat", "/proc/sys/kernel/osrelease"), 10),
    CommandSpec("kernel.hostname", "kernel", ("cat", "/proc/sys/kernel/hostname"), 10),
    CommandSpec("kernel.cmdline", "kernel", ("cat", "/proc/cmdline"), 10),
    CommandSpec("cpu.cpuinfo", "cpu", ("cat", "/proc/cpuinfo"), 10),
    CommandSpec("cpu.online_count", "cpu", ("getconf", "_NPROCESSORS_ONLN"), 10),
    CommandSpec("cpu.online_range", "cpu", ("cat", "/sys/devices/system/cpu/online"), 10),
)

DISPLAY_COMMANDS = (
    CommandSpec("display.wm_size", "display", ("wm", "size"), 10),
    CommandSpec("display.wm_density", "display", ("wm", "density"), 10),
    CommandSpec("display.dumpsys", "display", ("dumpsys", "display"), 20),
    CommandSpec("display.window_displays", "display", ("dumpsys", "window", "displays"), 20),
    CommandSpec(
        "display.forced_density",
        "display",
        ("settings", "get", "system", "display_density_forced"),
        10,
    ),
)

TELEPHONY_COMMANDS = (
    CommandSpec("telephony.registry", "telephony", ("dumpsys", "telephony.registry"), 20),
    CommandSpec("telephony.isub", "telephony", ("dumpsys", "isub"), 20),
    CommandSpec("telephony.telecom", "telephony", ("dumpsys", "telecom"), 20),
)

RUNTIME_COMMANDS = (
    CommandSpec("runtime.mount", "runtime_markers", ("mount",), 15),
    CommandSpec("runtime.proc_mounts", "runtime_markers", ("cat", "/proc/mounts"), 15),
    CommandSpec("runtime.processes", "runtime_markers", ("ps", "-A"), 15),
    CommandSpec("runtime.services", "runtime_markers", ("service", "list"), 15),
    CommandSpec("runtime.debug_ramdisk", "runtime_markers", ("ls", "-la", "/debug_ramdisk"), 10),
)

ROOT_RUNTIME_COMMANDS = (
    CommandSpec(
        "runtime.data_adb",
        "runtime_markers",
        ("su", "-c", "ls -la /data/adb 2>/dev/null"),
        10,
    ),
    CommandSpec(
        "runtime.data_adb_modules",
        "runtime_markers",
        ("su", "-c", "ls -la /data/adb/modules 2>/dev/null"),
        10,
    ),
    CommandSpec(
        "runtime.data_adb_magisk",
        "runtime_markers",
        ("su", "-c", "ls -la /data/adb/magisk 2>/dev/null"),
        10,
    ),
)

MAGISK_COMMANDS = (
    CommandSpec("magisk.version", "magisk", ("su", "-c", "magisk -v 2>/dev/null"), 10),
    CommandSpec("magisk.version_code", "magisk", ("su", "-c", "magisk -V 2>/dev/null"), 10),
    CommandSpec("magisk.path", "magisk", ("su", "-c", "magisk --path 2>/dev/null"), 10),
    CommandSpec(
        "magisk.settings",
        "magisk",
        ("su", "-c", 'magisk --sqlite "select key,value from settings;" 2>/dev/null'),
        15,
    ),
    CommandSpec(
        "magisk.modules",
        "magisk",
        ("su", "-c", "ls -1 /data/adb/modules 2>/dev/null"),
        10,
    ),
)

CAMERA_COMMANDS = (
    CommandSpec("camera.media_camera", "camera", ("dumpsys", "media.camera"), 20),
    CommandSpec("camera.cmd_list", "camera", ("cmd", "media.camera", "list"), 20),
    CommandSpec("camera.cmd_dump", "camera", ("cmd", "media.camera", "dump"), 30),
)

SENSOR_COMMANDS = (
    CommandSpec("sensors.sensorservice", "sensors", ("dumpsys", "sensorservice"), 20),
)

HAL_COMMANDS = (
    CommandSpec("hal.lshal", "hal", ("lshal",), 30),
    CommandSpec("hal.lshal_interfaces", "hal", ("lshal", "-i"), 30),
    CommandSpec("hal.dumpsys_services", "hal", ("dumpsys", "-l"), 20),
)

DEFAULT_PACKAGES = (
    "android",
    "com.google.android.gms",
    "com.android.vending",
    "com.google.android.apps.subscriptions.red",
    "com.google.android.googlequicksearchbox",
    "com.google.android.apps.bard",
)

_PACKAGE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")


@dataclass(frozen=True)
class _FixedCommandCollector:
    collector_id: str
    sections: tuple[str, ...]
    specs: tuple[CommandSpec, ...]

    def enabled(self, request: CollectionRequest) -> bool:
        return all(not request.skips(section) for section in self.sections)

    def collect(self, context: CollectorContext) -> CollectorResult:
        return CollectorResult(commands=tuple(context.run(spec) for spec in self.specs))


@dataclass(frozen=True)
class _PackageCollector:
    collector_id: str = "packages"
    sections: tuple[str, ...] = ("packages",)

    def enabled(self, request: CollectionRequest) -> bool:
        return not request.skips("packages")

    def collect(self, context: CollectorContext) -> CollectorResult:
        commands: list[EvidenceCommand] = []
        for package_name in context.request.packages:
            stem = package_name.replace(".", "_")
            path_spec = CommandSpec(
                f"packages.{stem}.path",
                "packages",
                ("cmd", "package", "path", package_name),
                20,
            )
            dumpsys_spec = CommandSpec(
                f"packages.{stem}.dumpsys",
                "packages",
                ("dumpsys", "package", package_name),
                20,
            )
            path_command = context.run(path_spec)
            dumpsys_command = context.run(dumpsys_spec)
            package_absent = _is_package_absence(path_command) or _is_package_absence(dumpsys_command)
            if package_absent:
                path_command = replace(path_command, status_override="observed")
                dumpsys_command = replace(dumpsys_command, status_override="observed")
            commands.extend((path_command, dumpsys_command))
        return CollectorResult(commands=tuple(commands))


@dataclass(frozen=True)
class _RootProbeCollector:
    collector_id: str = "root_probe"
    sections: tuple[str, ...] = ("magisk", "runtime_markers")

    def enabled(self, request: CollectionRequest) -> bool:
        return not request.skips("magisk") or not request.skips("runtime_markers")

    def collect(self, context: CollectorContext) -> CollectorResult:
        section = "magisk" if not context.request.skips("magisk") else "runtime_markers"
        path_spec = CommandSpec("root.su_path", section, ("command", "-v", "su"), 10)
        path_command = context.run(path_spec)
        commands = [path_command]
        root_available = False
        if command_status(path_command.result) == "observed" and path_command.result.stdout.strip():
            id_spec = CommandSpec("root.id", section, ("su", "-c", "id"), 10)
            id_command = context.run(id_spec)
            commands.append(id_command)
            root_available = command_status(id_command.result) == "observed" and bool(
                re.search(r"\buid=0(?:\(|\b)", id_command.result.stdout)
            )
        return CollectorResult(commands=tuple(commands), shared_updates={"root_available": root_available})


@dataclass(frozen=True)
class _MagiskCollector:
    collector_id: str = "magisk"
    sections: tuple[str, ...] = ("magisk",)

    def enabled(self, request: CollectionRequest) -> bool:
        return not request.skips("magisk")

    def collect(self, context: CollectorContext) -> CollectorResult:
        commands = [
            context.run(
                CommandSpec(
                    "magisk.cloud_property",
                    "magisk",
                    ("getprop", "ro.sys.cloud.magisk"),
                    10,
                )
            )
        ]
        if context.shared.get("root_available") is True:
            version_spec = MAGISK_COMMANDS[0]
            version_result = context.run(version_spec)
            version_status = "observed" if _is_command_absence(version_result) else None
            version_result = replace(version_result, status_override=version_status)
            commands.append(version_result)
            if command_status(version_result.result) == "observed" and version_result.result.stdout.strip():
                commands.extend(context.run(spec) for spec in MAGISK_COMMANDS[1:])
        return CollectorResult(commands=tuple(commands))


@dataclass(frozen=True)
class _RuntimeCollector:
    collector_id: str = "runtime_markers"
    sections: tuple[str, ...] = ("runtime_markers",)

    def enabled(self, request: CollectionRequest) -> bool:
        return not request.skips("runtime_markers")

    def collect(self, context: CollectorContext) -> CollectorResult:
        commands = [context.run(spec) for spec in RUNTIME_COMMANDS]
        if context.shared.get("root_available") is True:
            commands.extend(context.run(spec) for spec in ROOT_RUNTIME_COMMANDS)
        return CollectorResult(commands=tuple(commands))

@dataclass(frozen=True)
class _OptionalCommandCollector:
    collector_id: str
    sections: tuple[str, ...]
    specs: tuple[CommandSpec, ...]

    def enabled(self, request: CollectionRequest) -> bool:
        return all(not request.skips(section) for section in self.sections)

    def collect(self, context: CollectorContext) -> CollectorResult:
        commands: list[EvidenceCommand] = []
        for spec in self.specs:
            command = context.run(spec)
            if _is_unsupported_command(command):
                command = replace(command, status_override="unsupported")
            commands.append(command)
        return CollectorResult(commands=tuple(commands))


BUILTIN_COLLECTORS = cast(
    tuple[Collector, ...],
    (
    _FixedCommandCollector("transport_shell", ("transport",), PHASE_ONE_COMMANDS[:2]),
    _FixedCommandCollector("properties", ("properties",), (PHASE_ONE_COMMANDS[2],)),
    _FixedCommandCollector("kernel", ("kernel",), PHASE_ONE_COMMANDS[3:8]),
    _FixedCommandCollector("cpu", ("cpu",), PHASE_ONE_COMMANDS[8:]),
    _FixedCommandCollector("display", ("display",), DISPLAY_COMMANDS),
    _FixedCommandCollector("telephony", ("telephony",), TELEPHONY_COMMANDS),
    _PackageCollector(),
    _RootProbeCollector(),
    _MagiskCollector(),
    _RuntimeCollector(),
    _OptionalCommandCollector("camera", ("camera",), CAMERA_COMMANDS),
    _OptionalCommandCollector("sensors", ("sensors",), SENSOR_COMMANDS),
    _OptionalCommandCollector("hal", ("hal",), HAL_COMMANDS),
    ),
)


def normalize_packages(packages: tuple[str, ...]) -> tuple[str, ...]:
    """Validate and deterministically append custom packages to the defaults."""

    normalized: list[str] = []
    for package_name in (*DEFAULT_PACKAGES, *packages):
        if package_name != "android" and not _PACKAGE_NAME_PATTERN.fullmatch(package_name):
            raise ValueError(f"invalid package name: {package_name!r}")
        if package_name not in normalized:
            normalized.append(package_name)
    return tuple(normalized)


def _is_package_absence(command: EvidenceCommand) -> bool:
    text = f"{command.result.stdout}\n{command.result.stderr}".lower()
    return any(marker in text for marker in ("unknown package", "unable to find package", "package not found"))


def _is_command_absence(command: EvidenceCommand) -> bool:
    text = f"{command.result.stdout}\n{command.result.stderr}".lower()
    return "not found" in text or "inaccessible" in text

def _is_unsupported_command(command: EvidenceCommand) -> bool:
    text = f"{command.result.stdout} {command.result.stderr}".strip().lower()
    first_line = text.splitlines()[0] if text else ""
    return any(
        marker in first_line
        for marker in (
            "unknown command",
            "unknown option",
            "can't find service",
            "service not found",
            "not found",
            "inaccessible or not found",
            "not recognized",
        )
    )
