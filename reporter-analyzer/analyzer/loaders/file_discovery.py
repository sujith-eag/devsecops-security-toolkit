"""File discovery for raw scan result directories."""

from pathlib import Path

from analyzer.core.constants import KNOWN_INPUT_FILES
from analyzer.core.exceptions import InputValidationError


def discover_files(input_dir: Path) -> dict[str, Path]:
    """Return known files that exist in the input directory.

    Only files relevant to reporting are returned. Unknown files are ignored so
    the reporter remains stable when scanners add extra artifacts.
    """
    if not input_dir.exists():
        raise InputValidationError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise InputValidationError(f"Input path is not a directory: {input_dir}")

    return {
        filename: input_dir / filename
        for filename in KNOWN_INPUT_FILES
        if (input_dir / filename).is_file()
    }
