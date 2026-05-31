"""Cached data store over production org-data/current.

This is the main data access abstraction for the console. It loads production
index metadata, manifests, summary, validation, and exposes a manifest-based
resolver for query services.
"""

import re
from pathlib import Path

from console.data.entities import EntityResolver
from console.data.indexes import (
    load_by_artifact,
    load_by_package,
    load_by_vulnerability,
    load_manifests,
    load_remediation,
    read_json,
)
from console.data.resolver import DataResolver


def safe_filename(value):
    text = str(value or "unknown")
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    return text.strip("_") or "unknown"


def flatten_findings_document(data):
    findings = []
    grouped = data.get("findings", {}) if isinstance(data, dict) else {}
    for fixability_group in grouped.values():
        if not isinstance(fixability_group, dict):
            continue
        for severity_items in fixability_group.values():
            if isinstance(severity_items, list):
                findings.extend(severity_items)
    return findings


class DataStore:
    """Loads and caches org-data indexes, manifests, and entity resolvers."""

    def __init__(self, current_dir: Path):
        self.current_dir = current_dir
        self.entities = EntityResolver(current_dir)
        self.resolver = None
        self._artifact_findings_cache = {}
        self.reload()

    def reload(self):
        self.entities.reload()
        self._artifact_findings_cache = {}
        self.run_metadata = read_json(self.current_dir / "run" / "run-metadata.json", {}) or {}
        self.run_errors = read_json(self.current_dir / "run" / "run-errors.json", []) or []
        self.reference_warnings = read_json(self.current_dir / "run" / "reference-warnings.json", []) or []

        index_dir = self.current_dir / "indexes"
        self.index_metadata = read_json(index_dir / "index-metadata.json", {}) or {}
        self.index_summary = read_json(index_dir / "index-summary.json", {}) or {}
        self.index_validation = read_json(index_dir / "index-validation.json", {}) or {}
        self.manifests = load_manifests(index_dir)

        self.resolver = DataResolver(self.current_dir, self.manifests)

        # Compatibility/cache lists. Query code can use these lists for list pages,
        # while detail pages should prefer resolver lookups.
        self.by_artifact = load_by_artifact(index_dir)
        self.by_package = load_by_package(index_dir)
        self.by_vulnerability = load_by_vulnerability(index_dir)
        self.remediation = load_remediation(index_dir)

    def artifact_index(self, id_or_route):
        canonical = self.resolver.canonical("artifacts", id_or_route)
        return self.by_artifact.get(canonical) or self.resolver.artifact_index(canonical)

    def package_index(self, id_or_route):
        return self.resolver.package_index(id_or_route)

    def vulnerability_index(self, id_or_route):
        return self.resolver.vulnerability_index(id_or_route)

    def package_entity(self, id_or_route):
        return self.resolver.package_entity(id_or_route)

    def vulnerability_entity(self, id_or_route):
        return self.resolver.vulnerability_entity(id_or_route)

    def artifact_findings(self, artifact_id):
        artifact_id = self.resolver.canonical("artifacts", artifact_id)
        if artifact_id in self._artifact_findings_cache:
            return self._artifact_findings_cache[artifact_id]
        path = self.current_dir / "relationships" / "findings" / "by-artifact" / f"{safe_filename(artifact_id)}.json"
        data = read_json(path, {}) or {}
        findings = flatten_findings_document(data)
        self._artifact_findings_cache[artifact_id] = findings
        return findings