#!/usr/bin/env python3

import json
import os
import sys
from datetime import datetime, timezone

from analyzer.loaders import load_inputs
from analyzer.normalizer import normalize_matches
from analyzer.remediation import apply_remediation
from analyzer.summarizer import build_summary
from analyzer.markdown_writer import write_markdown_report
from analyzer.deduplicator import deduplicate_records



def fix_permissions(path):
    try:
        for root, dirs, files in os.walk(path):
            os.chmod(root, 0o775)
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o775)
            for f in files:
                os.chmod(os.path.join(root, f), 0o664)
    except Exception as exc:
        print(f"WARNING: permission normalization failed for {path}: {exc}")


def main():
    if len(sys.argv) != 3:
        print("Usage: python /app/analyzer/main.py <input-dir> <output-dir>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.isdir(input_dir):
        print(f"ERROR: input directory not found: {input_dir}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    metadata, grype_image, sbom, warnings = load_inputs(input_dir)

    raw_records = normalize_matches(grype_image)
    records = deduplicate_records(raw_records)
    records = apply_remediation(records)
    summary = build_summary(
        metadata=metadata,
        records=records,
        sbom=sbom,
        warnings=warnings,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        raw_match_count=len(raw_records),
    )

    summary_path = os.path.join(output_dir, "analysis-summary.json")
    report_path = os.path.join(output_dir, "analysis-report.md")

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=False)

    write_markdown_report(summary, report_path)

    fix_permissions(output_dir)

    print("Analysis completed successfully")
    print(f"Summary JSON: {summary_path}")
    print(f"Markdown report: {report_path}")


if __name__ == "__main__":
    main()
