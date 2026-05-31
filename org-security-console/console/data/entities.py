"""Entity resolvers for projects and artifact metadata.

Package and vulnerability entity resolution is delegated to DataResolver because
production manifests know the exact partition locations.
"""

from pathlib import Path
from urllib.parse import unquote

from console.data.indexes import read_json, records_from_payload


class EntityResolver:
    """Resolves small non-partitioned entity files."""

    def __init__(self, current_dir: Path):
        self.current_dir = current_dir
        self.artifacts = {}
        self.projects = {}
        self.reload()

    def reload(self):
        artifacts_payload = read_json(self.current_dir / "entities" / "artifacts.json", []) or []
        projects_payload = read_json(self.current_dir / "entities" / "projects.json", []) or []
        self.artifacts = {
            item.get("artifact_id"): item
            for item in records_from_payload(artifacts_payload)
            if item.get("artifact_id")
        }
        self.projects = {
            item.get("project_id"): item
            for item in records_from_payload(projects_payload)
            if item.get("project_id")
        }

    def get_artifact(self, artifact_id):
        artifact_id = artifact_id or ""
        return self.artifacts.get(artifact_id) or self.artifacts.get(unquote(artifact_id), {})

    def get_project(self, project_id):
        return self.projects.get(project_id or "", {})