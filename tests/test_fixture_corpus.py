from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from device_audit.analysis import analyze_bundle
from device_audit.bundle import load_evidence_bundle

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
EXPECTED_FIXTURE_COUNT = 119
EXPECTED_FIXTURE_DIGEST = "6a5eefef6d17de43211dafd98748cfa3192b7a765074a47d3c2ea4d7fd731055"
REQUIRED_FIXTURE_FAMILIES = {
    "aosp_emulator",
    "aosp_emulator_phase2",
    "bundles/schema_1_0",
    "bundles/schema_2_0",
    "malformed",
    "malformed_phase2",
    "permission_denied_phase2",
    "pixel_phase2",
    "pixel_reference",
    "samsung_phase2",
    "vmos_android13",
    "vmos_phase2",
}


def _fixture_files() -> list[Path]:
    return sorted(path for path in FIXTURE_ROOT.rglob("*") if path.is_file())


def _fixture_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(FIXTURE_ROOT).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def test_every_golden_fixture_is_content_locked_and_utf8_readable() -> None:
    paths = _fixture_files()

    assert len(paths) == EXPECTED_FIXTURE_COUNT
    assert _fixture_digest(paths) == EXPECTED_FIXTURE_DIGEST
    for path in paths:
        path.read_text(encoding="utf-8")


def test_golden_fixture_corpus_covers_every_release_family() -> None:
    observed_families = {
        path.relative_to(FIXTURE_ROOT).parent.as_posix()
        for path in _fixture_files()
    }

    assert REQUIRED_FIXTURE_FAMILIES <= observed_families


@pytest.mark.parametrize(
    ("fixture_name", "expected_schema", "expected_display_status"),
    (
        ("schema_1_0", "1.0", "not_evaluated"),
        ("schema_2_0", "2.0", "observed"),
    ),
)
def test_static_golden_bundle_replays_with_compatible_schema(
    fixture_name: str,
    expected_schema: str,
    expected_display_status: str,
    tmp_path: Path,
) -> None:
    bundle_dir = FIXTURE_ROOT / "bundles" / fixture_name
    manifest = load_evidence_bundle(bundle_dir)

    outcome = analyze_bundle(bundle_dir, tmp_path / fixture_name)
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == expected_schema
    assert report["bundle_schema_version"] == expected_schema
    assert report["source_bundle_digest"] == manifest["bundle_digest"]
    assert report["sections"]["display"]["status"] == expected_display_status
    assert outcome.collector_errors == 0
    for artifact in bundle_dir.rglob("*"):
        if artifact.is_file():
            assert "fixture-device-serial" not in artifact.read_text(encoding="utf-8")
