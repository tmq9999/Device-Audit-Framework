"""Command-line interface for collection, offline analysis, and composed audits."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Sequence

from device_audit import __version__
from device_audit.adb import ADBNotFoundError, DeviceSelectionError
from device_audit.analysis import analyze_bundle
from device_audit.bundle import BundleIntegrityError
from device_audit.capture import CaptureOptions, capture_evidence
from device_audit.profiles import ProfileValidationError, load_profile

EXIT_COMPLETE = 0
EXIT_COLLECTOR_ERRORS = 1
EXIT_INVALID_INPUT = 2
EXIT_ADB_UNAVAILABLE = 3
EXIT_DEVICE_UNAVAILABLE = 4
EXIT_WRITE_FAILURE = 5


def main(argv: Sequence[str] | None = None) -> int:
    """Run the device-audit CLI and return its stable process exit code."""

    parser = build_parser()
    arguments = _normalize_arguments(list(argv) if argv is not None else sys.argv[1:])
    namespace = parser.parse_args(arguments)
    try:
        if namespace.command == "collect":
            capture_outcome = capture_evidence(
                adb_path=namespace.adb_path,
                requested_serial=namespace.serial,
                output_dir=namespace.output_dir,
                timeout_seconds=namespace.timeout,
                options=_capture_options(namespace),
            )
            print(f"Evidence bundle: {capture_outcome.bundle_path}")
            return EXIT_COLLECTOR_ERRORS if capture_outcome.collector_errors else EXIT_COMPLETE

        if namespace.command == "analyze":
            if namespace.profile:
                load_profile(namespace.profile)
            analysis_outcome = analyze_bundle(namespace.bundle, namespace.output_dir, namespace.profile)
            print(f"Report: {analysis_outcome.report_path}")
            return EXIT_COLLECTOR_ERRORS if analysis_outcome.collector_errors else EXIT_COMPLETE

        if namespace.profile:
            load_profile(namespace.profile)
        capture_outcome = capture_evidence(
            adb_path=namespace.adb_path,
            requested_serial=namespace.serial,
            output_dir=namespace.output_dir,
            timeout_seconds=namespace.timeout,
            options=_capture_options(namespace),
        )
        analysis_outcome = analyze_bundle(
            capture_outcome.bundle_path,
            capture_outcome.bundle_path,
            namespace.profile,
        )
        print(f"Evidence bundle: {capture_outcome.bundle_path}")
        print(f"Report: {analysis_outcome.report_path}")
        if capture_outcome.collector_errors or analysis_outcome.collector_errors:
            return EXIT_COLLECTOR_ERRORS
        return EXIT_COMPLETE
    except (ProfileValidationError, BundleIntegrityError, ValueError) as error:
        print(f"Invalid input: {error}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    except ADBNotFoundError as error:
        print(f"ADB unavailable: {error}", file=sys.stderr)
        return EXIT_ADB_UNAVAILABLE
    except DeviceSelectionError as error:
        print(f"Device unavailable: {error}", file=sys.stderr)
        return EXIT_DEVICE_UNAVAILABLE
    except OSError as error:
        print(f"Artifact writing failure: {error}", file=sys.stderr)
        return EXIT_WRITE_FAILURE


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser for all supported workflows."""

    parser = argparse.ArgumentParser(description="Read-only Android device consistency audit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit", help="collect and analyze evidence")
    collect = subparsers.add_parser("collect", help="collect a redacted evidence bundle")
    analyze = subparsers.add_parser("analyze", help="analyze an existing evidence bundle")
    _add_capture_arguments(audit)
    audit.add_argument("--profile", type=Path, help="Expected profile JSON")
    _add_capture_arguments(collect)
    analyze.add_argument("--bundle", type=Path, required=True, help="Evidence bundle directory")
    analyze.add_argument("--output-dir", type=Path, required=True, help="Report output directory")
    analyze.add_argument("--profile", type=Path, help="Expected profile JSON")
    return parser


def _add_capture_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--adb-path", type=Path, required=True, help="Path to adb executable")
    parser.add_argument("--serial", help="Target serial; required when multiple devices are ready")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_default_output_dir(),
        help="Evidence bundle directory",
    )
    parser.add_argument("--timeout", type=_positive_integer, default=20, help="Default ADB timeout in seconds")
    parser.add_argument("--skip-display", action="store_true", help="Skip the read-only display collector")
    parser.add_argument("--skip-telephony", action="store_true", help="Skip telephony dumpsys collectors")
    parser.add_argument("--skip-packages", action="store_true", help="Skip package metadata collectors")
    parser.add_argument("--skip-magisk", action="store_true", help="Skip root-gated Magisk inventory")
    parser.add_argument(
        "--skip-runtime-markers",
        action="store_true",
        help="Skip filesystem and runtime marker collectors",
    )
    parser.add_argument("--skip-camera", action="store_true", help="Skip camera-service inventory")
    parser.add_argument("--skip-sensors", action="store_true", help="Skip sensorservice inventory")
    parser.add_argument("--skip-hal", action="store_true", help="Skip HAL and native-service inventory")
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        metavar="PACKAGE",
        help="Append a package to the audited package set (repeatable)",
    )


def _normalize_arguments(arguments: list[str]) -> list[str]:
    if arguments and arguments[0] == "--version":
        return arguments
    if not arguments or arguments[0] not in {"audit", "collect", "analyze"}:
        return ["audit", *arguments]
    return arguments


def _default_output_dir() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    return Path("audit_output") / f"run_{timestamp}"


def _positive_integer(value: str) -> int:
    integer = int(value)
    if integer <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return integer


def _capture_options(namespace: argparse.Namespace) -> CaptureOptions:
    return CaptureOptions(
        skip_display=namespace.skip_display,
        skip_telephony=namespace.skip_telephony,
        skip_packages=namespace.skip_packages,
        skip_magisk=namespace.skip_magisk,
        skip_runtime_markers=namespace.skip_runtime_markers,
        skip_camera=namespace.skip_camera,
        skip_sensors=namespace.skip_sensors,
        skip_hal=namespace.skip_hal,
        packages=tuple(namespace.package),
    )
