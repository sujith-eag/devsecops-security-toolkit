"""Cached data store over org-data/current.

This is the main file access abstraction. Web routes and reports should use the
query service rather than reading files directly.
"""

from pathlib import Path

from console.data.entities import EntityResolver
from console.data.indexes import load_by_artifact, load_by_package, load_by_vulnerability, load_remediation, read_json


class DataStore:
    """Loads and caches org-data indexes and entity resolvers."""

    def __init__(self, current_dir: Path):
        self.current_dir = current_dir
        self.entities = EntityResolver(current_dir)
        self.reload()

    def reload(self):
        self.entities.reload()
        self.run_metadata = read_json(self.current_dir / "run" / "run-metadata.json", {}) or {}
        self.run_errors = read_json(self.current_dir / "run" / "run-errors.json", []) or []
        self.reference_warnings = read_json(self.current_dir / "run" / "reference-warnings.json", []) or []
        index_dir = self.current_dir / "indexes"
        self.index_metadata = read_json(index_dir / "index-metadata.json", {}) or {}
        self.by_artifact = load_by_artifact(index_dir)
        self.by_package = load_by_package(index_dir)
        self.by_vulnerability = load_by_vulnerability(index_dir)
        self.remediation = load_remediation(index_dir)

    def artifact_index(self, artifact_id):
        return self.by_artifact.get(artifact_id or "", {})
