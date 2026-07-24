from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass
from pathlib import Path
import tomllib

import pytest

from device_audit import __version__
from device_audit.bundle import write_evidence_bundle
from device_audit.capture import DEFAULT_COLLECTOR_REGISTRY
from device_audit.cli import build_parser, main
from device_audit.collector_api import (
    COLLECTOR_API_VERSION,
    CollectionRequest,
    CollectorContext,
    CollectorRegistry,
    CollectorResult,
)
from device_audit.collectors import (
    AUDIO_COMMANDS,
    BATTERY_COMMANDS,
    BUILTIN_COLLECTORS,
    CAMERA_COMMANDS,
    DEFAULT_PACKAGES,
    DISPLAY_COMMANDS,
    GRAPHICS_COMMANDS,
    HAL_COMMANDS,
    INPUT_COMMANDS,
    MAGISK_COMMANDS,
    MEMORY_COMMANDS,
    NETWORK_COMMANDS,
    PHASE_ONE_COMMANDS,
    ROOT_RUNTIME_COMMANDS,
    RUNTIME_COMMANDS,
    SENSOR_COMMANDS,
    STORAGE_COMMANDS,
    TELEPHONY_COMMANDS,
    THERMAL_COMMANDS,
)
from device_audit.models import CommandResult, EvidenceCommand


def test_release_metadata_declares_v0100rc1_console_entrypoint() -> None:
    pyproject = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))

    assert __version__ == "0.12.0rc1"
    assert pyproject["project"]["version"] == __version__
    assert pyproject["project"]["scripts"] == {"device-audit": "device_audit.cli:main"}


def test_top_level_version_does_not_normalize_to_audit(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.endswith(" 0.12.0rc1\n")


def test_collector_api_registry_preserves_order_and_shared_state() -> None:
    events: list[str] = []

    @dataclass(frozen=True)
    class FirstCollector:
        collector_id: str = "first"
        sections: tuple[str, ...] = ("first",)

        def enabled(self, request: CollectionRequest) -> bool:
            return True

        def collect(self, context: CollectorContext) -> CollectorResult:
            events.append("first")
            assert context.shared == {}
            return CollectorResult(shared_updates={"ready": True})

    @dataclass(frozen=True)
    class SecondCollector:
        collector_id: str = "second"
        sections: tuple[str, ...] = ("second",)

        def enabled(self, request: CollectionRequest) -> bool:
            return True

        def collect(self, context: CollectorContext) -> CollectorResult:
            events.append("second")
            assert context.shared["ready"] is True
            return CollectorResult()

    run = CollectorRegistry((FirstCollector(), SecondCollector())).collect(object(), CollectionRequest())

    assert COLLECTOR_API_VERSION == "1.0"
    assert events == ["first", "second"]
    assert run.commands == ()
    assert run.shared == {"ready": True}


def test_builtin_collectors_are_uniquely_named_and_cover_current_sections() -> None:
    collector_ids = [collector.collector_id for collector in BUILTIN_COLLECTORS]
    sections = {section for collector in BUILTIN_COLLECTORS for section in collector.sections}

    assert collector_ids == [
        "transport_shell",
        "properties",
        "kernel",
        "cpu",
        "display",
        "telephony",
        "packages",
        "root_probe",
        "magisk",
        "runtime_markers",
        "camera",
        "sensors",
        "hal",
        "audio",
        "battery",
        "thermal",
        "storage",
        "network",
        "graphics",
        "input",
        "memory",
    ]
    assert sections == {
        "transport",
        "properties",
        "kernel",
        "cpu",
        "display",
        "telephony",
        "packages",
        "magisk",
        "runtime_markers",
        "camera",
        "sensors",
        "hal",
        "audio",
        "battery",
        "thermal",
        "storage",
        "network",
        "graphics",
        "input",
        "memory",
    }


def test_builtin_registry_is_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        DEFAULT_COLLECTOR_REGISTRY.collectors = ()


def test_frozen_builtin_command_specs_and_default_packages_are_exact() -> None:
    specs = (
        *PHASE_ONE_COMMANDS,
        *DISPLAY_COMMANDS,
        *TELEPHONY_COMMANDS,
        *MAGISK_COMMANDS,
        *RUNTIME_COMMANDS,
        *ROOT_RUNTIME_COMMANDS,
        *CAMERA_COMMANDS,
        *SENSOR_COMMANDS,
        *HAL_COMMANDS,
        *AUDIO_COMMANDS,
        *BATTERY_COMMANDS,
        *THERMAL_COMMANDS,
        *STORAGE_COMMANDS,
        *NETWORK_COMMANDS,
        *GRAPHICS_COMMANDS,
        *INPUT_COMMANDS,
        *MEMORY_COMMANDS,
    )

    assert [(spec.id, spec.section, spec.arguments, spec.timeout_seconds) for spec in specs] == [
        ("transport.id", "transport", ("id",), 10),
        ("transport.getenforce", "transport", ("getenforce",), 10),
        ("properties.getprop", "properties", ("getprop",), 15),
        ("kernel.uname", "kernel", ("uname", "-a"), 10),
        ("kernel.proc_version", "kernel", ("cat", "/proc/version"), 10),
        ("kernel.osrelease", "kernel", ("cat", "/proc/sys/kernel/osrelease"), 10),
        ("kernel.hostname", "kernel", ("cat", "/proc/sys/kernel/hostname"), 10),
        ("kernel.cmdline", "kernel", ("cat", "/proc/cmdline"), 10),
        ("cpu.cpuinfo", "cpu", ("cat", "/proc/cpuinfo"), 10),
        ("cpu.online_count", "cpu", ("getconf", "_NPROCESSORS_ONLN"), 10),
        ("cpu.online_range", "cpu", ("cat", "/sys/devices/system/cpu/online"), 10),
        ("display.wm_size", "display", ("wm", "size"), 10),
        ("display.wm_density", "display", ("wm", "density"), 10),
        ("display.dumpsys", "display", ("dumpsys", "display"), 20),
        ("display.window_displays", "display", ("dumpsys", "window", "displays"), 20),
        ("display.forced_density", "display", ("settings", "get", "system", "display_density_forced"), 10),
        ("telephony.registry", "telephony", ("dumpsys", "telephony.registry"), 20),
        ("telephony.isub", "telephony", ("dumpsys", "isub"), 20),
        ("telephony.telecom", "telephony", ("dumpsys", "telecom"), 20),
        ("magisk.version", "magisk", ("su", "-c", "magisk -v 2>/dev/null"), 10),
        ("magisk.version_code", "magisk", ("su", "-c", "magisk -V 2>/dev/null"), 10),
        ("magisk.path", "magisk", ("su", "-c", "magisk --path 2>/dev/null"), 10),
        (
            "magisk.settings",
            "magisk",
            ("su", "-c", 'magisk --sqlite "select key,value from settings;" 2>/dev/null'),
            15,
        ),
        ("magisk.modules", "magisk", ("su", "-c", "ls -1 /data/adb/modules 2>/dev/null"), 10),
        ("runtime.mount", "runtime_markers", ("mount",), 15),
        ("runtime.proc_mounts", "runtime_markers", ("cat", "/proc/mounts"), 15),
        ("runtime.processes", "runtime_markers", ("ps", "-A"), 15),
        ("runtime.services", "runtime_markers", ("service", "list"), 15),
        ("runtime.debug_ramdisk", "runtime_markers", ("ls", "-la", "/debug_ramdisk"), 10),
        (
            "runtime.data_adb",
            "runtime_markers",
            ("su", "-c", "ls -la /data/adb 2>/dev/null"),
            10,
        ),
        (
            "runtime.data_adb_modules",
            "runtime_markers",
            ("su", "-c", "ls -la /data/adb/modules 2>/dev/null"),
            10,
        ),
        (
            "runtime.data_adb_magisk",
            "runtime_markers",
            ("su", "-c", "ls -la /data/adb/magisk 2>/dev/null"),
            10,
        ),
        ("camera.media_camera", "camera", ("dumpsys", "media.camera"), 20),
        ("camera.cmd_list", "camera", ("cmd", "media.camera", "list"), 20),
        ("camera.cmd_dump", "camera", ("cmd", "media.camera", "dump"), 30),
        ("sensors.sensorservice", "sensors", ("dumpsys", "sensorservice"), 20),
        ("hal.lshal", "hal", ("lshal",), 30),
        ("hal.lshal_interfaces", "hal", ("lshal", "-i"), 30),
        ("hal.dumpsys_services", "hal", ("dumpsys", "-l"), 20),
        ("audio.dumpsys_audio", "audio", ("dumpsys", "audio"), 20),
        ("audio.audio_flinger", "audio", ("dumpsys", "media.audio_flinger"), 30),
        ("audio.audio_policy", "audio", ("dumpsys", "media.audio_policy"), 30),
        ("audio.policy_ports", "audio", ("cmd", "media.audio_policy", "list-audio-ports"), 20),
        ("audio.policy_patches", "audio", ("cmd", "media.audio_policy", "list-audio-patches"), 20),
        ("battery.dumpsys_battery", "battery", ("dumpsys", "battery"), 20),
        ("battery.properties", "battery", ("dumpsys", "batteryproperties"), 20),
        ("battery.cmd_status", "battery", ("cmd", "battery", "get-status"), 10),
        ("battery.cmd_health", "battery", ("cmd", "battery", "get-health"), 10),
        ("battery.cmd_level", "battery", ("cmd", "battery", "get-level"), 10),
        ("battery.cmd_plugged", "battery", ("cmd", "battery", "get-plugged"), 10),
        ("battery.cmd_current", "battery", ("cmd", "battery", "get-current"), 10),
        ("battery.cmd_temperature", "battery", ("cmd", "battery", "get-temperature"), 10),
        ("battery.cmd_counter", "battery", ("cmd", "battery", "get-counter"), 10),
        ("battery.cmd_charging_status", "battery", ("cmd", "battery", "get-charging-status"), 10),
        ("thermal.service", "thermal", ("dumpsys", "thermalservice"), 30),
        ("thermal.power", "thermal", ("dumpsys", "power"), 30),
        ("thermal.deviceidle", "thermal", ("dumpsys", "deviceidle"), 20),
        ("thermal.cmd_dump", "thermal", ("cmd", "thermalservice", "dump"), 30),
        ("thermal.power_mode", "thermal", ("cmd", "power", "get-mode"), 10),
        ("thermal.fixed_performance_mode", "thermal", ("cmd", "power", "get-fixed-performance-mode-enabled"), 10),
        ("storage.df_k", "storage", ("df", "-k"), 20),
        ("storage.mount", "storage", ("mount",), 20),
        ("storage.proc_mounts", "storage", ("cat", "/proc/mounts"), 20),
        ("storage.proc_filesystems", "storage", ("cat", "/proc/filesystems"), 15),
        ("storage.proc_partitions", "storage", ("cat", "/proc/partitions"), 15),
        ("storage.dumpsys_mount", "storage", ("dumpsys", "mount"), 30),
        ("storage.volumes", "storage", ("sm", "list-volumes", "all"), 20),
        ("storage.disks", "storage", ("sm", "list-disks"), 20),
        ("storage.primary_uuid", "storage", ("sm", "get-primary-storage-uuid"), 10),
        ("network.connectivity", "network", ("dumpsys", "connectivity"), 30),
        ("network.ip_link", "network", ("ip", "link"), 15),
        ("network.wifi_status", "network", ("cmd", "wifi", "status"), 15),
        ("network.airplane_mode", "network", ("settings", "get", "global", "airplane_mode_on"), 10),
        ("network.bluetooth_state", "network", ("settings", "get", "global", "bluetooth_on"), 10),
        ("graphics.surface_flinger", "graphics", ("dumpsys", "SurfaceFlinger"), 30),
        ("graphics.gpu", "graphics", ("dumpsys", "gpu"), 20),
        ("graphics.egl_property", "graphics", ("getprop", "ro.hardware.egl"), 10),
        ("graphics.vulkan_property", "graphics", ("getprop", "ro.hardware.vulkan"), 10),
        ("input.dumpsys", "input", ("dumpsys", "input"), 30),
        ("input.proc_devices", "input", ("cat", "/proc/bus/input/devices"), 15),
        ("memory.proc_meminfo", "memory", ("cat", "/proc/meminfo"), 10),
        ("memory.proc_swaps", "memory", ("cat", "/proc/swaps"), 10),
        ("memory.low_ram_property", "memory", ("getprop", "ro.config.low_ram"), 10),
    ]
    assert DEFAULT_PACKAGES == (
        "android",
        "com.google.android.gms",
        "com.android.vending",
        "com.google.android.apps.subscriptions.red",
        "com.google.android.googlequicksearchbox",
        "com.google.android.apps.bard",
    )


def test_frozen_cli_commands_and_flags_are_exact() -> None:
    parser = build_parser()
    top_level_flags = {
        option
        for action in parser._actions
        for option in action.option_strings
    }
    subparsers = next(
        action
        for action in parser._actions
        if getattr(action, "choices", None) is not None
    )

    assert top_level_flags == {"-h", "--help", "--version"}
    assert tuple(subparsers.choices) == ("audit", "collect", "analyze")
    assert _option_strings(subparsers.choices["audit"]) == {
        "-h",
        "--help",
        "--adb-path",
        "--serial",
        "--output-dir",
        "--timeout",
        "--skip-display",
        "--skip-telephony",
        "--skip-packages",
        "--skip-magisk",
        "--skip-runtime-markers",
        "--skip-camera",
        "--skip-sensors",
        "--skip-hal",
        "--skip-audio",
        "--skip-battery",
        "--skip-thermal",
        "--skip-storage",
        "--skip-network",
        "--skip-graphics",
        "--skip-input",
        "--skip-memory",
        "--package",
        "--profile",
    }
    assert _option_strings(subparsers.choices["collect"]) == {
        "-h",
        "--help",
        "--adb-path",
        "--serial",
        "--output-dir",
        "--timeout",
        "--skip-display",
        "--skip-telephony",
        "--skip-packages",
        "--skip-magisk",
        "--skip-runtime-markers",
        "--skip-camera",
        "--skip-sensors",
        "--skip-hal",
        "--skip-audio",
        "--skip-battery",
        "--skip-thermal",
        "--skip-storage",
        "--skip-network",
        "--skip-graphics",
        "--skip-input",
        "--skip-memory",
        "--package",
    }
    assert _option_strings(subparsers.choices["analyze"]) == {
        "-h",
        "--help",
        "--bundle",
        "--output-dir",
        "--profile",
    }


def test_frozen_bundle_artifact_names_are_exact(tmp_path: Path) -> None:
    bundle = write_evidence_bundle(
        tmp_path / "bundle",
        serial="fixture-serial",
        commands=[
            EvidenceCommand(
                "properties.getprop",
                "properties",
                CommandResult(("adb", "-s", "fixture-serial", "shell", "getprop"), 0, "", "", 0, False),
            )
        ],
    )

    assert {path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()} == {
        "evidence.json",
        "commands.jsonl",
        "audit.log",
        "raw/properties_getprop.stdout.txt",
        "raw/properties_getprop.stderr.txt",
    }


def test_root_probe_and_package_command_templates_are_frozen() -> None:
    calls: list[tuple[str, ...]] = []

    class RecordingClient:
        def shell(self, arguments: tuple[str, ...], timeout_seconds: int) -> CommandResult:
            calls.append(arguments)
            stdout = "ok\n"
            if arguments == ("command", "-v", "su"):
                stdout = "/system/bin/su\n"
            elif arguments == ("su", "-c", "id"):
                stdout = "uid=0(root) gid=0(root)\n"
            elif arguments == ("su", "-c", "magisk -v 2>/dev/null"):
                stdout = "v1\n"
            return CommandResult(("adb", *arguments), 0, stdout, "", 0, False)

    DEFAULT_COLLECTOR_REGISTRY.collect(
        RecordingClient(),
        CollectionRequest(
            skipped_sections=frozenset({"display", "telephony", "packages"}),
            packages=(),
        ),
    )
    assert ("command", "-v", "su") in calls
    assert ("su", "-c", "id") in calls

    calls.clear()
    DEFAULT_COLLECTOR_REGISTRY.collect(
        RecordingClient(),
        CollectionRequest(
            skipped_sections=frozenset({"display", "telephony", "magisk", "runtime_markers"}),
            packages=("com.example.fixture",),
        ),
    )
    assert [call for call in calls if call[:2] in {("cmd", "package"), ("dumpsys", "package")}] == [
        ("cmd", "package", "path", "com.example.fixture"),
        ("dumpsys", "package", "com.example.fixture"),
    ]


def test_registry_records_an_unexpected_collector_failure_and_continues() -> None:
    events: list[str] = []

    @dataclass(frozen=True)
    class BrokenCollector:
        collector_id: str = "broken"
        sections: tuple[str, ...] = ("broken",)

        def enabled(self, request: CollectionRequest) -> bool:
            return True

        def collect(self, context: CollectorContext) -> CollectorResult:
            raise RuntimeError("fixture-device-serial failed")

    @dataclass(frozen=True)
    class FollowingCollector:
        collector_id: str = "following"
        sections: tuple[str, ...] = ("following",)

        def enabled(self, request: CollectionRequest) -> bool:
            return True

        def collect(self, context: CollectorContext) -> CollectorResult:
            events.append("following")
            return CollectorResult(shared_updates={"completed": True})

    run = CollectorRegistry((BrokenCollector(), FollowingCollector())).collect(
        object(),
        CollectionRequest(),
    )

    assert events == ["following"]
    assert run.shared == {"completed": True}
    assert len(run.commands) == 1
    failure = run.commands[0]
    assert failure.id == "collector.broken.error"
    assert failure.section == "broken"
    assert failure.status_override == "unavailable"
    assert failure.result.command == ("<collector-error>", "broken")


def test_registry_rejects_an_undeclared_output_section() -> None:
    @dataclass(frozen=True)
    class InvalidCollector:
        collector_id: str = "invalid"
        sections: tuple[str, ...] = ("declared",)

        def enabled(self, request: CollectionRequest) -> bool:
            return True

        def collect(self, context: CollectorContext) -> CollectorResult:
            from device_audit.models import CommandResult, EvidenceCommand

            return CollectorResult(
                commands=(
                    EvidenceCommand(
                        "invalid.command",
                        "other",
                        CommandResult(("fixture",), 0, "", "", 0, False),
                    ),
                )
            )

    with pytest.raises(ValueError, match="undeclared section"):
        CollectorRegistry((InvalidCollector(),)).collect(object(), CollectionRequest())


def test_registry_rejects_duplicate_collector_and_command_ids() -> None:
    @dataclass(frozen=True)
    class DuplicateCollector:
        collector_id: str
        sections: tuple[str, ...]

        def enabled(self, request: CollectionRequest) -> bool:
            return True

        def collect(self, context: CollectorContext) -> CollectorResult:
            from device_audit.models import CommandResult, EvidenceCommand

            return CollectorResult(
                commands=(
                    EvidenceCommand(
                        "duplicate.command",
                        self.sections[0],
                        CommandResult(("fixture",), 0, "", "", 0, False),
                    ),
                )
            )

    with pytest.raises(ValueError, match="collector IDs must be unique"):
        CollectorRegistry(
            (
                DuplicateCollector("duplicate", ("first",)),
                DuplicateCollector("duplicate", ("second",)),
            )
        )

    registry = CollectorRegistry(
        (
            DuplicateCollector("first", ("first",)),
            DuplicateCollector("second", ("second",)),
        )
    )
    with pytest.raises(ValueError, match="duplicate evidence command ID"):
        registry.collect(object(), CollectionRequest())


def test_registry_does_not_run_a_disabled_collector() -> None:
    events: list[str] = []

    @dataclass(frozen=True)
    class DisabledCollector:
        collector_id: str = "disabled"
        sections: tuple[str, ...] = ("disabled",)

        def enabled(self, request: CollectionRequest) -> bool:
            return False

        def collect(self, context: CollectorContext) -> CollectorResult:
            events.append("unexpected")
            return CollectorResult()

    run = CollectorRegistry((DisabledCollector(),)).collect(object(), CollectionRequest())

    assert events == []
    assert run.commands == ()


def _option_strings(parser) -> set[str]:
    return {option for action in parser._actions for option in action.option_strings}
