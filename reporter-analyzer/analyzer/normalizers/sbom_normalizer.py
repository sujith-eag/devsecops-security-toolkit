"""Build a small inventory summary from CycloneDX SBOM data."""

from typing import Any


def build_inventory_summary(sbom_data: dict[str, Any] | None) -> dict[str, Any]:
    """Return a compact inventory summary for the initial report.

    The initial report intentionally avoids a full package inventory dump. That
    detail is better handled by org-data and later dedicated package reports.
    """
    if not sbom_data:
        return {
            "sbom_available": False,
            "component_count": 0,
            "package_type_counts": {},
        }

    components = sbom_data.get("components") or []
    package_type_counts: dict[str, int] = {}

    for component in components:
        if not isinstance(component, dict):
            continue
        package_type = str(component.get("type") or "unknown").lower()
        package_type_counts[package_type] = package_type_counts.get(package_type, 0) + 1

    return {
        "sbom_available": True,
        "component_count": len([c for c in components if isinstance(c, dict)]),
        "package_type_counts": dict(sorted(package_type_counts.items())),
    }
