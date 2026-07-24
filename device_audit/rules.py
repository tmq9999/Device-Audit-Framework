"""Profile-driven evidence rules for observable Phase 1 and Phase 2 data."""

from __future__ import annotations

import json
from collections.abc import Mapping
import re

from device_audit.models import (
    Comparison,
    CpuTopology,
    DisplayInfo,
    ExpectedProfile,
    Finding,
    KernelInfo,
    PackageInfo,
    TelephonyInfo,
)

_IDENTITY_PROPERTIES = {
    "brand": "ro.product.brand",
    "manufacturer": "ro.product.manufacturer",
    "model": "ro.product.model",
    "device": "ro.product.device",
    "product": "ro.product.name",
}
_BUILD_PROPERTIES = {
    "id": "ro.build.id",
    "incremental": "ro.build.version.incremental",
    "release": "ro.build.version.release",
    "sdk": "ro.build.version.sdk",
    "security_patch": "ro.build.version.security_patch",
    "fingerprint": "ro.build.fingerprint",
    "description": "ro.build.description",
}


def evaluate_profile(
    properties: dict[str, str],
    kernel: KernelInfo | None,
    cpu: CpuTopology | None,
    profile: ExpectedProfile | None,
    display: DisplayInfo | None = None,
    telephony: TelephonyInfo | None = None,
    packages: Mapping[str, PackageInfo] | None = None,
) -> list[Finding]:
    """Evaluate only those expectations explicitly declared by a profile."""

    comparisons = compare_profile(properties, kernel, cpu, profile, display, telephony, packages)
    findings: list[Finding] = []
    for comparison in comparisons:
        if comparison.status != "mismatched":
            continue
        if comparison.field == "kernel.lineage":
            findings.append(_kernel_finding(comparison))
        elif comparison.field == "native_cpu.topology":
            findings.append(_cpu_finding(comparison))
        elif comparison.category == "display":
            findings.append(_display_finding(comparison))
        elif comparison.category == "telephony":
            findings.append(_telephony_finding(comparison))
        elif comparison.category == "packages":
            findings.append(_package_finding(comparison))
        else:
            findings.append(_property_finding(comparison))
    return findings


def compare_profile(
    properties: dict[str, str],
    kernel: KernelInfo | None,
    cpu: CpuTopology | None,
    profile: ExpectedProfile | None,
    display: DisplayInfo | None = None,
    telephony: TelephonyInfo | None = None,
    packages: Mapping[str, PackageInfo] | None = None,
) -> list[Comparison]:
    """Return explicit matched, mismatched, or not-evaluated comparison states."""

    if profile is None:
        return []
    comparisons = _compare_property_fields(properties, profile.identity, _IDENTITY_PROPERTIES, "identity")
    comparisons.extend(_compare_property_fields(properties, profile.build, _BUILD_PROPERTIES, "build"))
    comparisons.append(_compare_kernel(kernel, profile))
    comparisons.append(_compare_cpu(cpu, profile))
    comparisons.extend(_compare_display(display, profile))
    comparisons.extend(_compare_telephony(telephony, profile))
    comparisons.extend(_compare_packages(packages or {}, profile))
    return comparisons


def _compare_property_fields(
    properties: dict[str, str],
    expected_fields: Mapping[str, str],
    property_names: dict[str, str],
    category: str,
) -> list[Comparison]:
    comparisons: list[Comparison] = []
    for field, expected in expected_fields.items():
        property_name = property_names.get(field)
        observed = properties.get(property_name) if property_name else None
        status = "not_evaluated" if observed is None else "matched" if observed == expected else "mismatched"
        comparisons.append(
            Comparison(
                field=f"{category}.{field}",
                category=category,
                status=status,
                expected=expected,
                observed=observed,
                evidence=(property_name or field,),
            )
        )
    return comparisons


def _compare_kernel(kernel: KernelInfo | None, profile: ExpectedProfile) -> Comparison:
    expected = ", ".join(profile.kernel_allowed_lineages) if profile.kernel_allowed_lineages else None
    observed = kernel.lineage if kernel else None
    if not profile.kernel_allowed_lineages or observed is None:
        status = "not_evaluated"
    else:
        status = "matched" if observed in profile.kernel_allowed_lineages else "mismatched"
    return Comparison(
        field="kernel.lineage",
        category="kernel",
        status=status,
        expected=expected,
        observed=observed,
        evidence=("kernel.osrelease",),
    )


def _compare_cpu(cpu: CpuTopology | None, profile: ExpectedProfile) -> Comparison:
    expected = [
        {
            "online_cpu_count": topology.online_cpu_count,
            "clusters": [cluster.__dict__ for cluster in topology.clusters],
        }
        for topology in profile.allowed_cpu_topologies
    ]
    observed_mapping = None
    if cpu is not None:
        observed_mapping = {
            "online_cpu_count": cpu.online_cpu_count,
            "clusters": [cluster.__dict__ for cluster in cpu.clusters],
        }
    if not profile.allowed_cpu_topologies or cpu is None or cpu.online_cpu_count is None:
        status = "not_evaluated"
    else:
        status = "matched" if any(cpu == allowed for allowed in profile.allowed_cpu_topologies) else "mismatched"
    return Comparison(
        field="native_cpu.topology",
        category="cpu",
        status=status,
        expected=json.dumps(expected, sort_keys=True) if expected else None,
        observed=json.dumps(observed_mapping, sort_keys=True) if observed_mapping else None,
        evidence=("cpuinfo", "online_cpu_count"),
    )


def _compare_display(display: DisplayInfo | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    if profile.display_allowed_physical_sizes:
        observed = display.physical_size if display else None
        comparisons.append(
            _allowed_comparison(
                "display.physical_size",
                "display",
                list(profile.display_allowed_physical_sizes),
                observed,
                ("display.wm_size",),
            )
        )
    if profile.display_allowed_density_ranges:
        observed_density = display.physical_density if display else None
        expected = json.dumps(
            [{"min": minimum, "max": maximum} for minimum, maximum in profile.display_allowed_density_ranges],
            sort_keys=True,
        )
        observed = str(observed_density) if observed_density is not None else None
        status = "not_evaluated" if observed_density is None else "matched" if any(
            minimum <= observed_density <= maximum
            for minimum, maximum in profile.display_allowed_density_ranges
        ) else "mismatched"
        comparisons.append(
            Comparison("display.physical_density", "display", status, expected, observed, ("display.wm_density",))
        )
    if profile.display_allowed_refresh_rates:
        observed_rates = list(display.refresh_rates) if display else None
        expected = json.dumps(list(profile.display_allowed_refresh_rates), sort_keys=True)
        observed = json.dumps(observed_rates, sort_keys=True) if observed_rates else None
        status = "not_evaluated" if not observed_rates else "matched" if set(observed_rates).issubset(
            set(profile.display_allowed_refresh_rates)
        ) else "mismatched"
        comparisons.append(
            Comparison("display.refresh_rates", "display", status, expected, observed, ("display.dumpsys",))
        )
    return comparisons


def _compare_telephony(telephony: TelephonyInfo | None, profile: ExpectedProfile) -> list[Comparison]:
    comparisons: list[Comparison] = []
    observed_values: dict[str, tuple[str, ...] | None] = {
        "operator_numeric": telephony.operator_numeric if telephony else None,
        "country_iso": telephony.operator_country_iso if telephony else None,
        "network_types": telephony.network_types if telephony else None,
        "ril_vendors": (telephony.ril_implementation,) if telephony and telephony.ril_implementation else None,
    }
    expectations = {
        "operator_numeric": profile.telephony_allowed_operator_numeric,
        "country_iso": profile.telephony_allowed_country_iso,
        "network_types": profile.telephony_allowed_network_types,
        "ril_vendors": profile.telephony_allowed_ril_vendors,
    }
    evidence = {
        "operator_numeric": ("properties.getprop", "telephony.registry"),
        "country_iso": ("properties.getprop", "telephony.registry"),
        "network_types": ("properties.getprop", "telephony.registry"),
        "ril_vendors": ("properties.getprop",),
    }
    for name, allowed in expectations.items():
        if allowed:
            observed_value = observed_values[name]
            comparisons.append(
                _allowed_comparison(
                    f"telephony.{name}",
                    "telephony",
                    list(allowed),
                    list(observed_value) if observed_value is not None else None,
                    evidence[name],
                )
            )
    if profile.telephony_allowed_baseband_patterns:
        observed = telephony.baseband if telephony else None
        expected = json.dumps(list(profile.telephony_allowed_baseband_patterns), sort_keys=True)
        status = "not_evaluated" if not observed else "matched" if any(
            re.search(pattern, observed) for pattern in profile.telephony_allowed_baseband_patterns
        ) else "mismatched"
        comparisons.append(
            Comparison("telephony.baseband", "telephony", status, expected, observed, ("properties.getprop",))
        )
    return comparisons


def _compare_packages(
    packages: Mapping[str, PackageInfo],
    profile: ExpectedProfile,
) -> list[Comparison]:
    comparisons: list[Comparison] = []
    for package_name, expectation in profile.package_expectations.items():
        package = packages.get(package_name)
        if expectation.required:
            observed = None if package is None or package.installed is None else str(package.installed).lower()
            comparisons.append(
                Comparison(
                    f"packages.{package_name}.installed",
                    "packages",
                    "not_evaluated" if observed is None else "matched" if observed == "true" else "mismatched",
                    "true",
                    observed,
                    (f"packages.{package_name}.path",),
                )
            )
        if expectation.allowed_version_code_ranges:
            observed_code = package.version_code if package and package.installed else None
            expected = json.dumps(
                [{"min": minimum, "max": maximum} for minimum, maximum in expectation.allowed_version_code_ranges],
                sort_keys=True,
            )
            status = "not_evaluated" if observed_code is None else "matched" if any(
                minimum <= observed_code <= maximum
                for minimum, maximum in expectation.allowed_version_code_ranges
            ) else "mismatched"
            comparisons.append(
                Comparison(
                    f"packages.{package_name}.version_code",
                    "packages",
                    status,
                    expected,
                    str(observed_code) if observed_code is not None else None,
                    (f"packages.{package_name}.dumpsys",),
                )
            )
        if expectation.required_enabled is not None:
            observed_enabled = package.enabled if package else None
            comparisons.append(
                Comparison(
                    f"packages.{package_name}.enabled",
                    "packages",
                    "not_evaluated" if observed_enabled is None else "matched" if observed_enabled == expectation.required_enabled else "mismatched",
                    str(expectation.required_enabled).lower(),
                    str(observed_enabled).lower() if observed_enabled is not None else None,
                    (f"packages.{package_name}.dumpsys",),
                )
            )
        if expectation.required_not_suspended:
            observed_suspended = package.suspended if package else None
            comparisons.append(
                Comparison(
                    f"packages.{package_name}.not_suspended",
                    "packages",
                    "not_evaluated" if observed_suspended is None else "matched" if observed_suspended is False else "mismatched",
                    "true",
                    str(not observed_suspended).lower() if observed_suspended is not None else None,
                    (f"packages.{package_name}.dumpsys",),
                )
            )
    return comparisons


def _allowed_comparison(
    field: str,
    category: str,
    allowed: list[str],
    observed: str | tuple[str, ...] | list[str] | None,
    evidence: tuple[str, ...],
) -> Comparison:
    expected = json.dumps(allowed, sort_keys=True)
    if observed is None or observed == []:
        status = "not_evaluated"
        observed_text = None
    else:
        values = [observed] if isinstance(observed, str) else list(observed)
        status = "matched" if all(value in allowed for value in values) else "mismatched"
        observed_text = json.dumps(values, sort_keys=True)
    return Comparison(field, category, status, expected, observed_text, evidence)


def _property_finding(comparison: Comparison) -> Finding:
    return Finding(
        id="PROFILE_FIELD_MISMATCH",
        title="Expected profile field differs",
        category=comparison.category,
        severity="medium",
        confidence="high",
        summary=f"Expected {comparison.field} to be {comparison.expected!r}, observed {comparison.observed!r}.",
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Review the selected profile and the observed property layer.",
    )


def _kernel_finding(comparison: Comparison) -> Finding:
    return Finding(
        id="KERNEL_LINEAGE_MISMATCH",
        title="Kernel lineage differs from profile reference",
        category="kernel",
        severity="medium",
        confidence="high",
        summary="The observable kernel lineage is not one of the profile's allowed lineages.",
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Confirm the profile's trusted kernel reference data before drawing conclusions.",
    )


def _cpu_finding(comparison: Comparison) -> Finding:
    return Finding(
        id="CPU_TOPOLOGY_MISMATCH",
        title="Native CPU topology differs from profile reference",
        category="cpu",
        severity="medium",
        confidence="high",
        summary="The observable CPU topology does not match any profile-declared topology.",
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Confirm the profile's trusted native CPU reference data before drawing conclusions.",
    )


def _display_finding(comparison: Comparison) -> Finding:
    return _phase2_finding(
        comparison,
        "DISPLAY_PROFILE_MISMATCH",
        "Display observation differs from the selected profile's explicit reference.",
    )


def _telephony_finding(comparison: Comparison) -> Finding:
    return _phase2_finding(
        comparison,
        "TELEPHONY_PROFILE_MISMATCH",
        "Telephony observation differs from the selected profile's explicit reference.",
    )


def _package_finding(comparison: Comparison) -> Finding:
    return _phase2_finding(
        comparison,
        "PACKAGE_PROFILE_MISMATCH",
        "Package metadata differs from the selected profile's explicit reference.",
    )


def _phase2_finding(comparison: Comparison, finding_id: str, summary: str) -> Finding:
    return Finding(
        id=finding_id,
        title="Explicit profile expectation differs",
        category=comparison.category,
        severity="medium",
        confidence="high",
        summary=summary,
        evidence=comparison.evidence,
        expected=comparison.expected,
        observed=comparison.observed,
        recommendation="Review the selected profile and the observed evidence before drawing conclusions.",
    )
