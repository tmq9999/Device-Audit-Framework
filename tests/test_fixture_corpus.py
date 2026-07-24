from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from device_audit.analysis import analyze_bundle
from device_audit.bundle import load_evidence_bundle

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
EXPECTED_FIXTURE_COUNT = 440
EXPECTED_FIXTURE_DIGEST = "c3224c297b84113f5da147adb461f30898dec86b553f130e27a39bf7a74d89dd"
REQUIRED_FIXTURE_FAMILIES = {
    "aosp_emulator",
    "aosp_emulator_phase2",
    "bundles/schema_1_0",
    "bundles/schema_2_0",
    "bundles/schema_3_0",
    "bundles/schema_4_0",
    "malformed",
    "malformed_phase2",
    "permission_denied_phase2",
    "permission_denied_phase3",
    "pixel_phase2",
    "pixel_phase3",
    "pixel_reference",
    "samsung_phase2",
    "samsung_phase3",
    "vmos_android13",
    "vmos_phase2",
    "vmos_phase3",
    "aosp_emulator_phase3",
    "lineage_phase3",
    "malformed_phase3",
    "pixel_phase4",
    "samsung_phase4",
    "vmos_phase4",
    "aosp_emulator_phase4",
    "lineage_phase4",
    "malformed_phase4",
    "permission_denied_phase4",
    "unsupported_commands_phase4",
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
    ("fixture_name", "expected_schema", "expected_display_status", "expected_phase3_status", "expected_phase4_status"),
    (
        ("schema_1_0", "1.0", "not_evaluated", "not_evaluated", "not_evaluated"),
        ("schema_2_0", "2.0", "observed", "not_evaluated", "not_evaluated"),
        ("schema_3_0", "3.0", "not_evaluated", "observed", "not_evaluated"),
        ("schema_4_0", "4.0", "not_evaluated", "not_evaluated", "observed"),
    ),
)
def test_static_golden_bundle_replays_with_compatible_schema(
    fixture_name: str,
    expected_schema: str,
    expected_display_status: str,
    expected_phase3_status: str,
    expected_phase4_status: str,
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
    assert report["sections"]["camera"]["status"] == expected_phase3_status
    assert report["sections"]["audio"]["status"] == expected_phase4_status
    assert report["sections"]["battery"]["status"] == expected_phase4_status
    assert report["sections"]["thermal"]["status"] == expected_phase4_status
    assert report["sections"]["storage"]["status"] == expected_phase4_status
    assert outcome.collector_errors == 0
    for artifact in bundle_dir.rglob("*"):
        if artifact.is_file():
            assert "fixture-device-serial" not in artifact.read_text(encoding="utf-8")
