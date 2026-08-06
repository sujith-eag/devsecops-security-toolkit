"""Manifest-based ID and partition resolver.

The console should use route IDs in URLs and resolve them back to canonical IDs
through production manifests. This avoids PURL encoding issues and prevents
partition guessing in the web/query layer.
"""

from pathlib import Path
from urllib.parse import unquote

from console.data.indexes import load_records


class DataResolver:
    """Resolves canonical IDs and route IDs to index/entity records."""

    def __init__(self, current_dir: Path, manifests: dict):
        self.current_dir = current_dir
        self.manifests = manifests
        self._route_maps = {}
        self._record_cache = {}
        self._build_route_maps()

    def reload(self, manifests: dict):
        self.manifests = manifests
        self._route_maps = {}
        self._record_cache = {}
        self._build_route_maps()

    def _build_route_maps(self):
        for name in ("artifacts", "packages", "vulnerabilities", "remediation"):
            mapping = self.manifests.get(name, {}) or {}
            self._route_maps[name] = {
                item.get("route_id"): canonical
                for canonical, item in mapping.items()
                if item.get("route_id")
            }

    def canonical(self, entity_type, id_or_route):
        value = id_or_route or ""
        mapping = self.manifests.get(entity_type, {}) or {}
        if value in mapping:
            return value
        if value in self._route_maps.get(entity_type, {}):
            return self._route_maps[entity_type][value]
        decoded = unquote(value)
        if decoded in mapping:
            return decoded
        return value

    def manifest_item(self, entity_type, id_or_route):
        canonical = self.canonical(entity_type, id_or_route)
        return canonical, (self.manifests.get(entity_type, {}) or {}).get(canonical, {})

    def _load_from_partition(self, entity_type, id_or_route, partition_key="partition", id_field="canonical_id"):
        canonical, manifest = self.manifest_item(entity_type, id_or_route)
        cache_key = (entity_type, canonical, partition_key)
        if cache_key in self._record_cache:
            return self._record_cache[cache_key]

        partition = manifest.get(partition_key)
        if not partition:
            return {}

        path = self.current_dir / partition
        for record in load_records(path):
            if record.get(id_field) == canonical or record.get(f"{entity_type[:-1]}_id") == canonical:
                self._record_cache[cache_key] = record
                return record
            if record.get("remediation_id") == canonical:
                self._record_cache[cache_key] = record
                return record
        return {}

    def artifact_index(self, id_or_route):
        return self._load_from_partition("artifacts", id_or_route, "partition", "canonical_id")

    def package_index(self, id_or_route):
        return self._load_from_partition("packages", id_or_route, "partition", "canonical_id")

    def vulnerability_index(self, id_or_route):
        return self._load_from_partition("vulnerabilities", id_or_route, "partition", "canonical_id")

    def package_entity(self, id_or_route):
        return self._load_from_partition("packages", id_or_route, "entity_partition", "package_id")

    def vulnerability_entity(self, id_or_route):
        return self._load_from_partition("vulnerabilities", id_or_route, "entity_partition", "vulnerability_id")