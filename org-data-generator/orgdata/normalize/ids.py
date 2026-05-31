"""
Shared identity and package normalization helpers.

Defines normalized package type handling, normalized PURL generation, fallback
package IDs, and finding IDs. This module is important because inventory data
and vulnerability data must produce matching package IDs.
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
    "maven": "maven",
    "gem": "gem",
    "cargo": "cargo",
    "nuget": "nuget",
    "composer": "composer",
}


def normalize_package_type(value):
    value = (value or "").strip().lower()
    return PACKAGE_TYPE_MAP.get(value, value or "unknown")


def package_type_from_purl(purl):
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return ""
    remainder = purl[4:]
    return remainder.split("/", 1)[0].split("@", 1)[0].split("?", 1)[0]


def normalize_purl(purl):
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return ""
    parts = urlsplit(purl)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def fallback_package_id(package_type, name, version):
    return "|".join([normalize_package_type(package_type), name or "", version or ""])


def package_id_from_values(purl, package_type, name, version):
    return normalize_purl(purl) or fallback_package_id(package_type, name, version)


def finding_id(artifact_id, vulnerability_id, package_id):
    return "|".join([artifact_id or "", vulnerability_id or "", package_id or ""])
