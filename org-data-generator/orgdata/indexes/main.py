"""
Standalone CLI entrypoint for building query indexes from org-data/current.

This can be called independently or invoked after base org-data generation. It
builds index files from normalized entities and relationships.
"""

import argparse
from pathlib import Path

from orgdata.indexes.builder import build_all_indexes
from orgdata.runtime.io import write_json


def main():
    parser = argparse.ArgumentParser(description="Build query indexes from normalized org-data current directory.")
    parser.add_argument("current_dir", help="Path to org-data/current")
    args = parser.parse_args()

    current_dir = Path(args.current_dir).resolve()
    if not current_dir.is_dir():
        raise SystemExit(f"Current org-data directory does not exist: {current_dir}")

    print(f"[org-data:indexes] Building indexes from {current_dir}", flush=True)
    metadata = build_all_indexes(current_dir)
    write_json(current_dir / "indexes" / "index-metadata.json", metadata)
    print(f"[org-data:indexes] Index build completed: {metadata}", flush=True)


if __name__ == "__main__":
    main()
