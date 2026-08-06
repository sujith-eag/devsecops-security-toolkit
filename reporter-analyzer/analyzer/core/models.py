"""Internal data models for the reporter analyzer."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class VulnerabilitySource:
    """Selected vulnerability input source for a scan result."""

    primary_file: str
    primary_type: str
    fallback_used: bool
    available_files: list[str]


@dataclass
class RawScanData:
    """Raw data bundle loaded from a single scan result directory."""

    input_dir: Path
    metadata: dict[str, Any]
    sbom: dict[str, Any] | None
    grype: dict[str, Any]
    vulnerability_source: VulnerabilitySource
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
