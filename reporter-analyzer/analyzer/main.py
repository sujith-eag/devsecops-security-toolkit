"""Reporter Analyzer CLI.

Initial mode consumes a single raw scan result directory and writes report
outputs from the stable initial report data contract.
"""

import argparse
import sys
from pathlib import Path

from analyzer.builders.initial_report_builder import build_initial_report
from analyzer.core.exceptions import ReporterError
from analyzer.loaders.raw_scan_loader import load_raw_scan
from analyzer.normalizers.grype_normalizer import normalize_grype_matches
from analyzer.normalizers.sbom_normalizer import build_inventory_summary
from analyzer.processors.deduplicator import deduplicate_findings
from analyzer.processors.remediation import remediation_highlights, top_affected_packages
from analyzer.processors.risk_ranker import rank_findings, top_vulnerabilities
from analyzer.renderers.html_renderer import render_initial_html
from analyzer.renderers.json_renderer import write_json_report
from analyzer.renderers.pdf_renderer import render_initial_pdf

SUPPORTED_FORMATS = {"json", "html", "pdf"}


def _add_initial_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("initial", help="Generate initial scan report outputs")
    parser.add_argument("--input-dir", required=True, help="Raw scan result directory")
    parser.add_argument("--output-dir", required=True, help="Directory where report outputs will be written")
    parser.add_argument(
        "--formats",
        nargs="+",
        default=["json", "html", "pdf"],
        choices=sorted(SUPPORTED_FORMATS),
        help="Output formats to generate. Default: json html pdf",
    )
    parser.add_argument(
        "--logo-path",
        default="",
        help="Optional logo path available inside the reporter container. If omitted, templates/org-logo.png is used when present.",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DevSecOps reporter analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_initial_parser(subparsers)
    return parser.parse_args(argv)


def _build_initial_report_data(input_dir: str) -> dict:
    raw_scan = load_raw_scan(input_dir)
    findings = normalize_grype_matches(raw_scan.grype, raw_scan.vulnerability_source.primary_file)
    findings = deduplicate_findings(findings)
    findings = rank_findings(findings)

    return build_initial_report(
        raw_scan=raw_scan,
        findings=findings,
        inventory_summary=build_inventory_summary(raw_scan.sbom),
        top_vulnerabilities=top_vulnerabilities(findings),
        top_affected_packages=top_affected_packages(findings),
        remediation_highlights=remediation_highlights(findings),
    )


def run_initial(input_dir: str, output_dir: str, formats: list[str], logo_path: str = "") -> list[str]:
    """Run initial report pipeline and return generated output paths."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    report_data = _build_initial_report_data(input_dir)
    generated: list[str] = []

    if "json" in formats:
        generated.append(str(write_json_report(report_data, output)))

    html = None
    if "html" in formats or "pdf" in formats:
        html_path = output / "initial-security-report.html"
        html = render_initial_html(report_data, html_path, logo_path=logo_path)
        if "html" in formats:
            generated.append(str(html_path))

    if "pdf" in formats:
        pdf_path = output / "initial-security-report.pdf"
        render_initial_pdf(html or "", pdf_path)
        generated.append(str(pdf_path))

    return generated


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    try:
        if args.command == "initial":
            outputs = run_initial(args.input_dir, args.output_dir, args.formats, args.logo_path)
            print("Generated report outputs:")
            for output in outputs:
                print(f"- {output}")
            return 0
        raise ReporterError(f"Unsupported command: {args.command}")
    except ReporterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())