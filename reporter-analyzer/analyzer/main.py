"""Reporter Analyzer CLI.

Initial mode consumes a single raw scan result directory and writes a stable
`initial-report-data.json` file. Later modes can reuse the same architecture for
HTML/PDF and org-data reports.
"""

import argparse
import sys

from analyzer.builders.initial_report_builder import build_initial_report
from analyzer.core.exceptions import ReporterError
from analyzer.loaders.raw_scan_loader import load_raw_scan
from analyzer.normalizers.grype_normalizer import normalize_grype_matches
from analyzer.normalizers.sbom_normalizer import build_inventory_summary
from analyzer.processors.deduplicator import deduplicate_findings
from analyzer.processors.remediation import remediation_highlights, top_affected_packages
from analyzer.processors.risk_ranker import rank_findings, top_vulnerabilities
from analyzer.renderers.json_renderer import write_json_report


def _add_initial_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("initial", help="Generate initial report data from one raw scan result folder")
    parser.add_argument("--input-dir", required=True, help="Raw scan result directory")
    parser.add_argument("--output-dir", required=True, help="Directory where report data will be written")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DevSecOps reporter analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_initial_parser(subparsers)
    return parser.parse_args(argv)


def run_initial(input_dir: str, output_dir: str) -> str:
    """Run the complete initial report data pipeline."""
    raw_scan = load_raw_scan(input_dir)
    findings = normalize_grype_matches(raw_scan.grype, raw_scan.vulnerability_source.primary_file)
    findings = deduplicate_findings(findings)
    findings = rank_findings(findings)

    inventory_summary = build_inventory_summary(raw_scan.sbom)
    report_data = build_initial_report(
        raw_scan=raw_scan,
        findings=findings,
        inventory_summary=inventory_summary,
        top_vulnerabilities=top_vulnerabilities(findings),
        top_affected_packages=top_affected_packages(findings),
        remediation_highlights=remediation_highlights(findings),
    )

    return str(write_json_report(report_data, output_dir))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    try:
        if args.command == "initial":
            output_path = run_initial(args.input_dir, args.output_dir)
            print(f"Initial report data written: {output_path}")
            return 0
        raise ReporterError(f"Unsupported command: {args.command}")
    except ReporterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
