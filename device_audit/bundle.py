"""Versioned, redacted evidence-bundle persistence and verification."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from collections.abc import Iterable, Mapping
from typing import Any

from device_audit import __version__
from device_audit.models import CommandResult, EvidenceCommand
from device_audit.redaction import redact_arguments, redact_text


class BundleIntegrityError(ValueError):
    """Raised when a bundle is malformed or an artifact digest differs."""


def write_evidence_bundle(
    output_dir: Path,
    serial: str,
    commands: list[EvidenceCommand],
    additional_sensitive_values: Iterable[str] = (),
    collector_states: Mapping[str, str] | None = None,
    schema_version: str = "2.0",
) -> Path:
    """Write a redacted, self-describing evidence bundle."""

    sensitive_values = tuple({serial, *additional_sensitive_values})
    output_dir = _sanitize_output_dir(Path(output_dir), sensitive_values)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    command_entries: list[dict[str, Any]] = []
    log_lines: list[str] = []

    for command in commands:
        result = command.result
        stem = _safe_stem(command.id)
        stdout_path = raw_dir / f"{stem}.stdout.txt"
        stderr_path = raw_dir / f"{stem}.stderr.txt"
        stdout = _canonical_text(redact_text(result.stdout, sensitive_values))
        stderr = _canonical_text(redact_text(result.stderr, sensitive_values))
        stdout_path.write_text(stdout, encoding="utf-8", newline="\n")
        stderr_path.write_text(stderr, encoding="utf-8", newline="\n")
        status = command.status_override or command_status(result)
        entry = {
            "id": command.id,
            "section": command.section,
            "command": redact_arguments(result.command, serial=serial),
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "timed_out": result.timed_out,
            "status": status,
            "stdout_path": str(stdout_path.relative_to(output_dir)).replace("\\", "/"),
            "stderr_path": str(stderr_path.relative_to(output_dir)).replace("\\", "/"),
            "stdout_sha256": sha256_text(stdout),
            "stderr_sha256": sha256_text(stderr),
            "stdout_length": len(stdout),
            "stderr_length": len(stderr),
        }
        command_entries.append(entry)
        log_lines.append(
            f"{_timestamp()} command={command.id} status={status} "
            f"exit_code={result.exit_code} duration_ms={result.duration_ms} "
            f"stdout_length={len(stdout)} stderr_length={len(stderr)} timeout={result.timed_out}"
        )

    commands_jsonl = "".join(f"{_json_line(entry)}\n" for entry in command_entries)
    audit_log = "\n".join(log_lines) + "\n"
    manifest: dict[str, Any] = {
        "schema_version": schema_version,
        "bundle_type": "device-audit-evidence",
        "generated_at": _timestamp(),
        "tool_version": __version__,
        "target": {"serial": "<redacted-serial>"},
        "commands": command_entries,
        "commands_jsonl_sha256": sha256_text(commands_jsonl),
        "audit_log_sha256": sha256_text(audit_log),
    }
    if schema_version in {"2.0", "3.0", "4.0"}:
        default_states = {
            "display": "not_evaluated",
            "telephony": "not_evaluated",
            "packages": "not_evaluated",
            "magisk": "not_evaluated",
            "runtime_markers": "not_evaluated",
        }
        if schema_version in {"3.0", "4.0"}:
            default_states.update(
                {
                    "camera": "not_evaluated",
                    "sensors": "not_evaluated",
                    "hal": "not_evaluated",
                }
            )
        if schema_version == "4.0":
            default_states.update(
                {
                    "audio": "not_evaluated",
                    "battery": "not_evaluated",
                    "thermal": "not_evaluated",
                    "storage": "not_evaluated",
                }
            )
        manifest["collector_states"] = dict(collector_states or default_states)
    manifest["bundle_digest"] = _manifest_digest(manifest)
    (output_dir / "evidence.json").write_text(_json_text(manifest), encoding="utf-8", newline="\n")
    (output_dir / "commands.jsonl").write_text(commands_jsonl, encoding="utf-8", newline="\n")
    (output_dir / "audit.log").write_text(audit_log, encoding="utf-8", newline="\n")
    return output_dir


def load_evidence_bundle(bundle_dir: Path) -> dict[str, Any]:
    """Load and verify a persisted evidence bundle."""

    bundle_dir = Path(bundle_dir)
    evidence_path = bundle_dir / "evidence.json"
    try:
        manifest = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleIntegrityError(f"unable to read evidence manifest: {error}") from error
    schema_version = manifest.get("schema_version")
    if schema_version not in {"1.0", "2.0", "3.0", "4.0"} or manifest.get("bundle_type") != "device-audit-evidence":
        raise BundleIntegrityError("unsupported evidence bundle schema")
    _validate_manifest_metadata(manifest)
    stored_digest = manifest.get("bundle_digest")
    if not isinstance(stored_digest, str) or stored_digest != _manifest_digest(manifest):
        raise BundleIntegrityError("evidence manifest digest does not match")
    commands = manifest.get("commands")
    if not isinstance(commands, list):
        raise BundleIntegrityError("evidence manifest commands must be a list")
    for command in commands:
        _validate_command_entry(command)
    if schema_version in {"2.0", "3.0", "4.0"}:
        _validate_collector_states(manifest.get("collector_states"), schema_version)
    _verify_metadata_artifact(bundle_dir, "commands.jsonl", manifest.get("commands_jsonl_sha256"))
    _verify_metadata_artifact(bundle_dir, "audit.log", manifest.get("audit_log_sha256"))
    _verify_commands_jsonl(bundle_dir / "commands.jsonl", commands)
    for command in commands:
        for key in ("stdout_path", "stderr_path", "stdout_sha256", "stderr_sha256"):
            if not isinstance(command[key], str):
                raise BundleIntegrityError(f"evidence command missing {key}")
        for path_key, digest_key in (("stdout_path", "stdout_sha256"), ("stderr_path", "stderr_sha256")):
            path = _safe_artifact_path(bundle_dir, command[path_key])
            if not path.exists():
                raise BundleIntegrityError(f"missing evidence artifact: {command[path_key]}")
            if sha256_text(path.read_text(encoding="utf-8")) != command[digest_key]:
                raise BundleIntegrityError(f"artifact digest mismatch: {command[path_key]}")
    _verify_declared_raw_artifacts(bundle_dir, commands)
    return manifest


def command_status(result: CommandResult) -> str:
    """Map a command result to an explicit evidence state."""

    if result.timed_out:
        return "timeout"
    if result.exit_code == 0:
        return "observed"
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if any(
        marker in combined
        for marker in ("permission denied", "permission denial", "not permitted", "security exception")
    ):
        return "permission_denied"
    return "unavailable"


def sha256_text(text: str) -> str:
    """Return the SHA-256 digest of UTF-8 text."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _manifest_digest(manifest: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in manifest.items() if key != "bundle_digest"}
    return sha256_text(_json_text(unsigned))


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _json_line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonical_text(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _safe_stem(value: str) -> str:
    return "".join(character if character.isalnum() or character in "-_" else "_" for character in value)


def _sanitize_output_dir(output_dir: Path, sensitive_values: Iterable[str]) -> Path:
    output_text = str(output_dir)
    for value in sorted({value for value in sensitive_values if value}, key=len, reverse=True):
        output_text = output_text.replace(value, "redacted")
    return Path(output_text)


def _safe_artifact_path(bundle_dir: Path, relative_path: str) -> Path:
    path = (bundle_dir / relative_path).resolve()
    root = bundle_dir.resolve()
    if root != path and root not in path.parents:
        raise BundleIntegrityError("evidence artifact escapes bundle directory")
    return path


def _verify_metadata_artifact(bundle_dir: Path, file_name: str, expected_digest: Any) -> None:
    if not isinstance(expected_digest, str):
        raise BundleIntegrityError(f"evidence manifest missing digest for {file_name}")
    path = bundle_dir / file_name
    if not path.exists():
        raise BundleIntegrityError(f"missing required bundle artifact: {file_name}")
    contents = path.read_text(encoding="utf-8")
    if sha256_text(contents) != expected_digest:
        raise BundleIntegrityError(f"artifact digest mismatch: {file_name}")


def _verify_commands_jsonl(path: Path, commands: list[Any]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != len(commands):
        raise BundleIntegrityError("commands.jsonl does not match evidence command count")
    for index, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise BundleIntegrityError("commands.jsonl contains invalid JSON") from error
        if not isinstance(entry, dict) or entry.get("id") != commands[index].get("id"):
            raise BundleIntegrityError("commands.jsonl does not match evidence command metadata")


def _validate_command_entry(command: Any) -> None:
    if not isinstance(command, dict):
        raise BundleIntegrityError("evidence command entry must be an object")
    for key in ("id", "section", "status", "stdout_path", "stderr_path", "stdout_sha256", "stderr_sha256"):
        if not isinstance(command.get(key), str):
            raise BundleIntegrityError(f"evidence command missing {key}")
    if not isinstance(command.get("command"), list) or not all(
        isinstance(argument, str) for argument in command["command"]
    ):
        raise BundleIntegrityError("evidence command arguments must be a list of strings")
    if command["status"] not in {
        "observed",
        "timeout",
        "permission_denied",
        "unsupported",
        "unavailable",
        "parse_error",
        "not_evaluated",
    }:
        raise BundleIntegrityError("evidence command has an invalid status")
    arguments = command["command"]
    if "-s" in arguments:
        serial_index = arguments.index("-s") + 1
        if serial_index >= len(arguments) or arguments[serial_index] != "<redacted-serial>":
            raise BundleIntegrityError("evidence command contains an unredacted serial")


def _validate_manifest_metadata(manifest: dict[str, Any]) -> None:
    target = manifest.get("target")
    if not isinstance(target, dict) or target.get("serial") != "<redacted-serial>":
        raise BundleIntegrityError("evidence target metadata is not redacted")
    if not isinstance(manifest.get("tool_version"), str) or not manifest["tool_version"]:
        raise BundleIntegrityError("evidence manifest is missing tool_version")
    if not isinstance(manifest.get("generated_at"), str) or not manifest["generated_at"]:
        raise BundleIntegrityError("evidence manifest is missing generated_at")


def _validate_collector_states(value: Any, schema_version: str) -> None:
    if not isinstance(value, dict):
        raise BundleIntegrityError("evidence manifest collector_states must be an object")
    expected_sections = {"display", "telephony", "packages", "magisk", "runtime_markers"}
    if schema_version in {"3.0", "4.0"}:
        expected_sections.update({"camera", "sensors", "hal"})
    if schema_version == "4.0":
        expected_sections.update({"audio", "battery", "thermal", "storage"})
    if set(value) != expected_sections:
        raise BundleIntegrityError("evidence manifest collector_states is incomplete")
    valid_states = {
        "observed",
        "timeout",
        "permission_denied",
        "unsupported",
        "unavailable",
        "parse_error",
        "not_evaluated",
    }
    if not all(isinstance(state, str) and state in valid_states for state in value.values()):
        raise BundleIntegrityError("evidence manifest collector_states has an invalid value")

def _verify_declared_raw_artifacts(bundle_dir: Path, commands: list[Any]) -> None:
    declared = {
        relative_path
        for command in commands
        for relative_path in (command["stdout_path"], command["stderr_path"])
    }
    raw_dir = bundle_dir / "raw"
    if not raw_dir.exists():
        return
    actual = {
        path.relative_to(bundle_dir).as_posix()
        for path in raw_dir.rglob("*")
        if path.is_file()
    }
    undeclared = sorted(actual - declared)
    if undeclared:
        raise BundleIntegrityError(f"undeclared evidence artifacts: {', '.join(undeclared)}")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
