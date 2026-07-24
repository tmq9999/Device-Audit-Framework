"""Stable read-only collector plugin contracts.

The v1 API deliberately exposes command specifications rather than a raw shell
escape hatch. Built-in collectors are the only collectors shipped by v0.11.0rc1;
future plugins must still be reviewed against the project command whitelist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Protocol

from device_audit.adb import ADBClient, ADBNotFoundError
from device_audit.models import CommandResult, EvidenceCommand


COLLECTOR_API_VERSION = "1.0"


@dataclass(frozen=True)
class CommandSpec:
    """One bounded, read-only Android shell command declared by a collector."""

    id: str
    section: str
    arguments: tuple[str, ...]
    timeout_seconds: int

    def __post_init__(self) -> None:
        if not self.id or not self.section or not self.arguments:
            raise ValueError("collector command specs require id, section, and arguments")
        if any(not isinstance(argument, str) or not argument for argument in self.arguments):
            raise ValueError("collector command arguments must be non-empty strings")
        if self.timeout_seconds <= 0:
            raise ValueError("collector command timeout must be positive")


@dataclass(frozen=True)
class CollectionRequest:
    """Capture options passed to built-in and third-party collectors."""

    skipped_sections: frozenset[str] = frozenset()
    packages: tuple[str, ...] = ()
    timeout_seconds: int = 20

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("collection timeout must be positive")

    def skips(self, section: str) -> bool:
        """Return whether a section was explicitly skipped for this run."""

        return section in self.skipped_sections


@dataclass(frozen=True)
class CollectorContext:
    """Read-only execution context exposed to a collector implementation."""

    client: ADBClient
    request: CollectionRequest
    shared: Mapping[str, object] = field(default_factory=dict)

    def run(self, spec: CommandSpec, status_override: str | None = None) -> EvidenceCommand:
        """Execute one declared command through the serial-explicit ADB client."""

        return EvidenceCommand(
            id=spec.id,
            section=spec.section,
            result=self.client.shell(spec.arguments, timeout_seconds=spec.timeout_seconds),
            status_override=status_override,
        )


@dataclass(frozen=True)
class CollectorResult:
    """Commands and bounded shared state emitted by one collector."""

    commands: tuple[EvidenceCommand, ...] = ()
    shared_updates: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class CollectionRun:
    """Complete ordered output of a collector registry run."""

    commands: tuple[EvidenceCommand, ...]
    shared: Mapping[str, object]


class Collector(Protocol):
    """Protocol implemented by built-in and future reviewed collectors."""

    collector_id: str
    sections: tuple[str, ...]

    def enabled(self, request: CollectionRequest) -> bool:
        """Return whether this collector participates in the current request."""

    def collect(self, context: CollectorContext) -> CollectorResult:
        """Collect only the commands declared by this collector."""


@dataclass(frozen=True)
class CollectorRegistry:
    """Ordered collector registry with duplicate and output validation."""

    collectors: tuple[Collector, ...]

    def __post_init__(self) -> None:
        collector_ids = [collector.collector_id for collector in self.collectors]
        if len(collector_ids) != len(set(collector_ids)):
            raise ValueError("collector IDs must be unique")
        if any(not collector_id for collector_id in collector_ids):
            raise ValueError("collector IDs must be non-empty")
        if any(
            not collector.sections
            or any(not isinstance(section, str) or not section for section in collector.sections)
            for collector in self.collectors
        ):
            raise ValueError("collector sections must contain non-empty strings")

    def collect(self, client: ADBClient, request: CollectionRequest) -> CollectionRun:
        """Run enabled collectors in declaration order."""

        commands: list[EvidenceCommand] = []
        shared: dict[str, object] = {}
        command_ids: set[str] = set()
        for collector in self.collectors:
            if not collector.enabled(request):
                continue
            context = CollectorContext(client, request, MappingProxyType(dict(shared)))
            try:
                result = collector.collect(context)
            except ADBNotFoundError:
                raise
            except Exception as error:
                failure = _collector_failure(collector, error)
                if failure.id in command_ids:
                    raise ValueError(f"duplicate evidence command ID: {failure.id}") from error
                command_ids.add(failure.id)
                commands.append(failure)
                continue
            for command in result.commands:
                if command.section not in collector.sections:
                    raise ValueError(
                        f"collector {collector.collector_id!r} emitted undeclared section "
                        f"{command.section!r}"
                    )
                if command.id in command_ids:
                    raise ValueError(f"duplicate evidence command ID: {command.id}")
                command_ids.add(command.id)
                commands.append(command)
            shared.update(result.shared_updates)
        return CollectionRun(commands=tuple(commands), shared=MappingProxyType(shared))

def _collector_failure(collector: Collector, error: Exception) -> EvidenceCommand:
    return EvidenceCommand(
        id=f"collector.{collector.collector_id}.error",
        section=collector.sections[0],
        result=CommandResult(
            command=("<collector-error>", collector.collector_id),
            exit_code=1,
            stdout="",
            stderr=f"{type(error).__name__}: {error}",
            duration_ms=0,
            timed_out=False,
        ),
        status_override="unavailable",
    )
