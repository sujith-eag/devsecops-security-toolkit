"""
Parses scanner metadata into normalized artifact and project records.

The result folder name is used as fallback `artifact_id`. Project metadata is
optional; artifacts without project metadata are still included as artifact-only
records.
"""

def parse_metadata(metadata, folder_name):
    artifact_id = metadata.get("artifact_id") or folder_name
    artifact_type = metadata.get("artifact_type") or (metadata.get("scan") or {}).get("scan_type") or "unknown"
    project = metadata.get("project") or {}

    artifact = {
        "artifact_id": artifact_id,
        "artifact_folder": folder_name,
        "artifact_type": artifact_type,
        "artifact_role": metadata.get("artifact_role", ""),
        "schema_version": metadata.get("schema_version", ""),
        "project_id": project.get("project_id", ""),
        "image": metadata.get("image") or {},
        "source": metadata.get("source") or {},
        "scan": metadata.get("scan") or {},
        "paths": metadata.get("paths") or {},
    }

    # Legacy metadata fallback for older image scans.
    if not artifact["image"] and any(key in metadata for key in ("image_ref", "digest_value", "image_id")):
        artifact["image"] = {
            "image_ref": metadata.get("image_ref", ""),
            "image_source": metadata.get("image_source", ""),
            "repo_digest": metadata.get("repo_digest", ""),
            "digest_value": metadata.get("digest_value", ""),
            "short_digest": metadata.get("short_digest", ""),
            "image_id": metadata.get("image_id", ""),
            "image_os": metadata.get("image_os", ""),
            "image_architecture": metadata.get("image_architecture", ""),
            "image_created": metadata.get("image_created", ""),
        }

    project_record = None
    if project.get("project_id"):
        project_record = {
            "project_id": project.get("project_id", ""),
            "project_name": project.get("project_name", ""),
            "project_type": project.get("project_type", ""),
            "project_repository": project.get("project_repository", ""),
            "project_branch": project.get("project_branch", ""),
            "project_commit": project.get("project_commit", ""),
        }

    project_artifact = None
    if project_record:
        project_artifact = {
            "project_id": project_record["project_id"],
            "artifact_id": artifact_id,
            "relationship_type": "owns_or_produces",
        }

    return artifact, project_record, project_artifact
