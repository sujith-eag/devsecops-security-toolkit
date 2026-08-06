"""Render a small, standalone HTML inventory from a CycloneDX SBOM."""

import html
import json
from pathlib import Path
from typing import Any

from analyzer.normalizers.package_identity import normalize_purl, normalized_package_type


def _text(value: Any) -> str:
    """Return a displayable value, using a dash for absent values."""
    if value is None or value == "":
        return "-"
    return str(value)


def _license(component: dict[str, Any]) -> str:
    licenses = component.get("licenses")
    if not isinstance(licenses, list):
        return "-"
    values: list[str] = []
    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        license_data = entry.get("license")
        if isinstance(license_data, dict):
            value = license_data.get("name") or license_data.get("id")
            if value:
                values.append(str(value))
                continue
        expression = entry.get("expression")
        if expression:
            values.append(str(expression))
    return ", ".join(values) if values else "-"


def _components(input_dir: Path) -> list[dict[str, Any]]:
    source = input_dir / "sbom-cyclonedx.json"
    try:
        with source.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError, TypeError):
        return []
    if not isinstance(document, dict) or not isinstance(document.get("components"), list):
        return []
    return [component for component in document["components"] if isinstance(component, dict)]


def _inventory_components(input_dir: Path) -> list[dict[str, Any]]:
    """Return sorted, package-like components for the readable inventory."""
    candidates = []
    for component in _components(input_dir):
        purl = normalize_purl(component.get("purl"))
        # A valid PURL identifies a package even when the scanner labels it as
        # an operating-system component. File/OS entries without PURLs are noise.
        if not purl or purl == "pkg:":
            continue
        candidates.append(component)

    # Sort before collapsing identities so the retained record is deterministic.
    candidates.sort(
        key=lambda component: (
            _text(component.get("name")).casefold(),
            _text(component.get("version")).casefold(),
            normalize_purl(component.get("purl")).casefold(),
            normalized_package_type(component.get("type"), component.get("purl")),
        )
    )
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for component in candidates:
        purl = normalize_purl(component.get("purl"))
        identity = (
            purl,
            _text(component.get("name")),
            _text(component.get("version")),
            normalized_package_type(component.get("type"), purl),
        )
        unique.setdefault(identity, component)
    return list(unique.values())


def render_sbom_html(input_dir: str | Path, output_path: str | Path) -> Path:
    """Write a self-contained HTML inventory and return its path."""
    rows = _inventory_components(Path(input_dir))
    rendered_rows = []
    for component in rows:
        values = (
            _text(component.get("name")),
            _text(component.get("version")),
            normalized_package_type(component.get("type"), component.get("purl")),
            _text(component.get("purl")),
            _license(component),
        )
        rendered_rows.append("<tr>" + "".join(f"<td>{html.escape(value)}</td>" for value in values) + "</tr>")
    body = "\n".join(rendered_rows)
    message = "" if rows else '<p class="empty">No SBOM components were found.</p>'
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBOM Inventory</title>
<style>
body {{ font-family: system-ui, sans-serif; color: #1f2937; margin: 2rem; }}
h1 {{ margin-bottom: .25rem; }}
.summary {{ color: #4b5563; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1.5rem; }}
th, td {{ border: 1px solid #d1d5db; padding: .55rem .7rem; text-align: left; vertical-align: top; }}
th {{ background: #f3f4f6; }}
.empty {{ padding: 1rem; background: #f9fafb; border: 1px solid #d1d5db; }}
</style>
</head>
<body>
<h1>SBOM Inventory</h1>
<p class="summary">Package count: {len(rows)}</p>
{message}
<table>
<thead><tr><th>Package</th><th>Version</th><th>Type/ecosystem</th><th>PURL</th><th>License</th></tr></thead>
<tbody>{body}</tbody>
</table>
</body>
</html>
"""
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")
    return destination
