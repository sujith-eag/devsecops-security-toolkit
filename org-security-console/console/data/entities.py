"""Entity loaders and ID-based resolvers for artifacts, packages, and vulnerabilities."""

from pathlib import Path
from urllib.parse import unquote

from console.data.indexes import read_json, load_json_files


def same_id(left, right):
    """Compare IDs while tolerating URL-decoded route values.

    Package IDs can contain percent-encoded characters such as `%3A`. Flask may
    provide decoded route values, while org-data files keep the normalized PURL
    form. This helper prevents lookup failures for those IDs.
    """
    left = left or ""
    right = right or ""
    return left == right or unquote(left) == right or left == unquote(right) or unquote(left) == unquote(right)


def package_type_from_id(package_id: str):
    package_id = package_id or ""
    if package_id.startswith("pkg:"):
        remainder = package_id[4:]
        return remainder.split("/", 1)[0].split("@", 1)[0].split("?", 1)[0]
    decoded = unquote(package_id)
    if decoded.startswith("pkg:"):
        remainder = decoded[4:]
        return remainder.split("/", 1)[0].split("@", 1)[0].split("?", 1)[0]
    return package_id.split("|", 1)[0] if "|" in package_id else "unknown"


def vulnerability_bucket(vulnerability_id: str):
    text = vulnerability_id or "other"
    if text.startswith("CVE-"):
        parts = text.split("-")
        return f"CVE-{parts[1]}" if len(parts) > 1 and parts[1].isdigit() else "CVE-other"
    if text.startswith("GHSA-"):
        return "GHSA"
    return "other"


class EntityResolver:
    """Resolves normalized entity IDs to entity metadata from org-data partitions."""

    def __init__(self, current_dir: Path):
        self.current_dir = current_dir
        self.artifacts = {}
        self.projects = {}
        self._package_cache = {}
        self._vulnerability_cache = {}
        self.reload()

    def reload(self):
        self.artifacts = {
            item.get("artifact_id"): item
            for item in (read_json(self.current_dir / "entities" / "artifacts.json", []) or [])
            if item.get("artifact_id")
        }
        self.projects = {
            item.get("project_id"): item
            for item in (read_json(self.current_dir / "entities" / "projects.json", []) or [])
            if item.get("project_id")
        }
        self._package_cache = {}
        self._vulnerability_cache = {}

    def get_artifact(self, artifact_id):
        artifact_id = artifact_id or ""
        return self.artifacts.get(artifact_id) or self.artifacts.get(unquote(artifact_id), {})

    def get_project(self, project_id):
        return self.projects.get(project_id or "", {})

    def get_package(self, package_id):
        package_id = package_id or ""
        if package_id in self._package_cache:
            return self._package_cache[package_id]

        package_type = package_type_from_id(package_id)
        path = self.current_dir / "entities" / "packages" / "by-type" / f"{package_type}.json"
        for item in read_json(path, []) or []:
            if same_id(item.get("package_id"), package_id):
                self._package_cache[package_id] = item
                self._package_cache[item.get("package_id")] = item
                return item
        return {}

    def get_vulnerability(self, vulnerability_id):
        vulnerability_id = unquote(vulnerability_id or "")
        if vulnerability_id in self._vulnerability_cache:
            return self._vulnerability_cache[vulnerability_id]
        bucket = vulnerability_bucket(vulnerability_id)
        path = self.current_dir / "entities" / "vulnerabilities" / "by-year" / f"{bucket}.json"
        for item in read_json(path, []) or []:
            if item.get("vulnerability_id") == vulnerability_id:
                self._vulnerability_cache[vulnerability_id] = item
                return item
        return {}

    def all_packages(self):
        return load_json_files(self.current_dir / "entities" / "packages" / "by-type")

    def all_vulnerabilities(self):
        return load_json_files(self.current_dir / "entities" / "vulnerabilities" / "by-year")