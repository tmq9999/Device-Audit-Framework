# Collector API

The stable collector API version in v0.11.0-rc.1 is `1.0`.

## Contract

Implementations satisfy the `Collector` protocol:

```python
class Collector(Protocol):
    collector_id: str
    sections: tuple[str, ...]

    def enabled(self, request: CollectionRequest) -> bool: ...
    def collect(self, context: CollectorContext) -> CollectorResult: ...
```

Use `CommandSpec` for every Android command. A spec has a stable ID, section,
argument tuple, and positive timeout. `CollectorContext.run(spec)` executes
the spec through the serial-bound `ADBClient`; it is not a raw shell escape
hatch.

`CollectorResult` returns evidence commands and optional bounded shared state.
The ordered `CollectorRegistry` validates unique collector IDs and evidence
command IDs, rejects undeclared output sections, and passes a read-only
snapshot of shared state to each enabled collector. An unexpected collector
exception becomes a redacted `collector.<id>.error` evidence record and later
collectors continue. A missing ADB executable remains a process-level error.

## Compatibility rules

Built-ins preserve their Phase 1/2 command IDs, argument order, timeouts,
section names, package handling, root gate, and declaration order. Phase 3
adds `camera`, `sensors`, and `hal`; Phase 4 adds `audio`, `battery`, `thermal`,
and `storage`, all with stable command IDs. Do not rename an existing command
ID or change its arguments in a maintenance release: bundle replay and report
provenance depend on them.

No automatic entry-point scanning is enabled. A future application may inject
an explicitly reviewed registry, but the default registry must remain the
frozen built-in set.

## Adding a future collector

Collector additions are outside the frozen Phase 4 milestone. A future
contributor must:

1. document every new command and its read-only rationale;
2. add the command to a reviewed whitelist snapshot;
3. define fixtures for observed, unavailable, timeout, permission, and parse
   error paths;
4. preserve redaction before persistence;
5. ensure failure is recorded without aborting other collectors; and
6. add an offline replay test and update architecture documentation; and
7. preserve schemas `1.0`, `2.0`, `3.0`, and `4.0` replay compatibility.

The Phase 3 built-ins use this API for read-only camera, sensor, and HAL
commands. Phase 4 uses it for metadata-only audio, battery, thermal/power, and
storage commands; it never plays or records audio, samples sensors, writes
power state, benchmarks storage, or runs a second full `getprop`. Collectors
mark version-dependent unavailable commands as `unsupported`; the registry
records those results and continues with later collectors.

Do not use `shell=True`, host-shell interpolation, arbitrary command strings,
mutating Android commands, or recursive sensitive filesystem collection.
