from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from device_audit.models import CpuCluster, CpuTopology, KernelInfo
from device_audit.parsers import parse_cpuinfo, parse_getprop, parse_kernel_info
from device_audit.profiles import ProfileValidationError, load_profile
from device_audit.redaction import redact_text
from device_audit.rules import evaluate_profile

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_getprop_returns_key_value_mapping() -> None:
    properties = parse_getprop((FIXTURES / "getprop.txt").read_text(encoding="utf-8"))

    assert properties["ro.build.version.release"] == "16"
    assert properties["ro.product.model"] == "Pixel 10 Pro"


def test_parse_kernel_info_extracts_explicit_lineage() -> None:
    kernel = parse_kernel_info((FIXTURES / "uname.txt").read_text(encoding="utf-8"))

    assert kernel.release == "5.10.107-android13-4-00003-g777901393eee-ab8910922"
    assert kernel.lineage == "android13-5.10"
    assert kernel.architecture == "aarch64"


def test_parse_kernel_info_does_not_invent_a_lineage() -> None:
    kernel = parse_kernel_info("Linux host 6.1.0-custom aarch64")

    assert kernel.lineage is None


def test_parse_cpuinfo_groups_parts_and_uses_online_cpu_count() -> None:
    topology = parse_cpuinfo(
        (FIXTURES / "cpuinfo.txt").read_text(encoding="utf-8"),
        online_cpu_count=8,
    )

    assert topology.online_cpu_count == 8
    assert topology.clusters == (
        CpuCluster(implementer="0x41", part="0xd05", count=4),
        CpuCluster(implementer="0x41", part="0xd41", count=2),
        CpuCluster(implementer="0x41", part="0xd44", count=2),
    )


def test_redaction_removes_sensitive_identifiers_without_removing_build_number() -> None:
    fixture_email = "fixture.user@" + "example.invalid"
    redacted = redact_text(
        f"serial TEST-SERIAL-0001 IMEI: TEST-IMEI-0001 email: {fixture_email} "
        "Android ID: a1b2c3d4e5f67890 build 15081906"
    )

    assert "TEST-SERIAL-0001" not in redacted
    assert "TEST-IMEI-0001" not in redacted
    assert fixture_email not in redacted
    assert "a1b2c3d4e5f67890" not in redacted
    assert "15081906" in redacted


def test_load_profile_reads_optional_native_references(tmp_path) -> None:
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "name": "Reference device",
                "identity": {"model": "Reference"},
                "build": {"release": "16", "sdk": 36},
                "kernel": {"allowed_lineages": ["android13-5.10"]},
                "native_cpu": {
                    "allowed_topologies": [
                        {
                            "online_cpu_count": 2,
                            "clusters": [
                                {"implementer": "0x41", "part": "0xd05", "count": 2}
                            ],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    profile = load_profile(profile_path)

    assert profile.identity["model"] == "Reference"
    assert profile.kernel_allowed_lineages == ("android13-5.10",)
    assert profile.allowed_cpu_topologies[0].online_cpu_count == 2


def test_load_profile_rejects_invalid_topology(tmp_path) -> None:
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "name": "Broken",
                "native_cpu": {"allowed_topologies": [{"clusters": []}]},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ProfileValidationError, match="online_cpu_count"):
        load_profile(profile_path)


def test_profile_evaluation_only_flags_referenced_layers() -> None:
    findings = evaluate_profile(
        properties={"ro.product.model": "Different model"},
        kernel=KernelInfo(release="5.10.107-android13", lineage="android13-5.10"),
        cpu=CpuTopology(
            online_cpu_count=2,
            clusters=(CpuCluster(implementer="0x41", part="0xd05", count=2),),
        ),
        profile=load_profile_from_mapping(
            {
                "schema_version": "1.0",
                "name": "Reference",
                "identity": {"model": "Expected model"},
            }
        ),
    )

    assert [finding.id for finding in findings] == ["PROFILE_FIELD_MISMATCH"]
    assert findings[0].observed == "Different model"


def test_profile_evaluation_flags_declared_kernel_and_cpu_references() -> None:
    findings = evaluate_profile(
        properties={},
        kernel=KernelInfo(release="5.10.107-android13", lineage="android13-5.10"),
        cpu=CpuTopology(
            online_cpu_count=2,
            clusters=(CpuCluster(implementer="0x41", part="0xd05", count=2),),
        ),
        profile=load_profile_from_mapping(
            {
                "schema_version": "1.0",
                "name": "Reference",
                "kernel": {"allowed_lineages": ["android14-6.1"]},
                "native_cpu": {
                    "allowed_topologies": [
                        {
                            "online_cpu_count": 2,
                            "clusters": [
                                {"implementer": "0x41", "part": "0xd44", "count": 2}
                            ],
                        }
                    ]
                },
            }
        ),
    )

    assert {finding.id for finding in findings} == {
        "KERNEL_LINEAGE_MISMATCH",
        "CPU_TOPOLOGY_MISMATCH",
    }


def load_profile_from_mapping(payload: dict) -> object:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(payload, handle)
        profile_path = Path(handle.name)
    try:
        return load_profile(profile_path)
    finally:
        profile_path.unlink()
