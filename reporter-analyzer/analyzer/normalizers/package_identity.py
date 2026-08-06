"""Package identity and package type normalization helpers.

This is a lightweight version of the org-data package normalization logic. It
keeps the initial report clean without trying to build the full org-data entity
model.
"""

from urllib.parse import urlsplit, urlunsplit

PACKAGE_TYPE_MAP = {
    "go-module": "golang",
    "golang": "golang",
    "java-archive": "maven",
    "jar": "maven",
    "python-package": "python",
    "apk": "apk",
    "deb": "deb",
    "rpm": "rpm",
    "npm": "npm",
    "pypi": "python",
    "maven": "maven",
    "gem": "gem",
    "cargo": "cargo",
    "nuget": "nuget",
    "composer": "composer",
    "library": "library",
    "file": "file",
    "operating-system": "operating-system",
}

NOISY_SBOM_COMPONENT_TYPES = {"file", "operating-system"}


def normalize_package_type(value: object) -> str:
    """Normalize scanner package/component type into a stable value."""
    normalized = str(value or "").strip().lower()
    return PACKAGE_TYPE_MAP.get(normalized, normalized or "unknown")


def package_type_from_purl(purl: object) -> str:
    """Extract package ecosystem/type from a Package URL, if present."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return ""
    remainder = purl[4:]
    return remainder.split("/", 1)[0].split("@", 1)[0].split("?", 1)[0]


def normalize_purl(purl: object) -> str:
    """Normalize PURL by removing query and fragment portions."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return ""
    parts = urlsplit(purl)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def normalized_package_type(raw_type: object = None, purl: object = None) -> str:
    """Derive package type using PURL first, then scanner-reported type.

    This avoids common noise where scanners report generic values such as
    `library` or `file` even when the PURL contains the real ecosystem.
    """
    purl_type = package_type_from_purl(purl)
    if purl_type:
        return normalize_package_type(purl_type)
    return normalize_package_type(raw_type)


def is_noisy_sbom_component(component_type: object) -> bool:
    """Return True for SBOM components that should not affect inventory counts."""
    return normalize_package_type(component_type) in NOISY_SBOM_COMPONENT_TYPES