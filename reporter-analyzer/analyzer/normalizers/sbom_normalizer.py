"""Build a small inventory summary from CycloneDX SBOM data."""

from typing import Any

from analyzer.normalizers.package_identity import is_noisy_sbom_component, normalized_package_type


def build_inventory_summary(sbom_data: dict[str, Any] | None) -> dict[str, Any]:
    """Return a compact inventory summary for the initial report.

    File and operating-system SBOM components are intentionally ignored here.
    They are noisy for initial reporting and should not inflate package counts.
    Vulnerability findings are handled separately and are not dropped based on
    package type.
    """
    if not sbom_data:
        return {
            "sbom_available": False,
            "component_count": 0,
            "package_type_counts": {},
        }

    components = sbom_data.get("components") or []
    included_component_count = 0
    package_type_counts: dict[str, int] = {}

    for component in components:
        if not isinstance(component, dict):
            continue

        component_type = component.get("type") or "unknown"
        if is_noisy_sbom_component(component_type):
            continue

        included_component_count += 1
        package_type = normalized_package_type(raw_type=component_type, purl=component.get("purl"))
        package_type_counts[package_type] = package_type_counts.get(package_type, 0) + 1

    return {
        "sbom_available": True,
        "component_count": included_component_count,
        "package_type_counts": dict(sorted(package_type_counts.items())),
    }