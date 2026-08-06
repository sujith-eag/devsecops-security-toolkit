"""
Grype integration utilities.

Handles Grype version lookup, database update/status check, SBOM vulnerability
scan execution, and JSON formatting using `jq` to match the scanner output style.
"""

import json
import os
import subprocess
from pathlib import Path


def run_command(args, timeout=None):
    completed = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=os.environ.copy())
    return {"returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr, "command": args}


def get_grype_version():
    result = run_command(["grype", "version", "-o", "json"], timeout=60)
    if result["returncode"] == 0:
        try:
            return json.loads(result["stdout"])
        except Exception:
            return {"raw": result["stdout"].strip()}
    return {"returncode": result["returncode"], "stderr": result["stderr"].strip(), "stdout": result["stdout"].strip()}


def update_grype_db():
    update = run_command(["grype", "db", "update"], timeout=600)
    status = run_command(["grype", "db", "status", "-o", "json"], timeout=120)
    parsed_status = None
    if status["returncode"] == 0:
        try:
            parsed_status = json.loads(status["stdout"])
        except Exception:
            parsed_status = {"raw": status["stdout"].strip()}
    else:
        parsed_status = {"returncode": status["returncode"], "stderr": status["stderr"].strip()}
    return {"update": {"returncode": update["returncode"], "stdout": update["stdout"].strip(), "stderr": update["stderr"].strip()}, "status": parsed_status}


def pretty_json_file(path: Path):
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    result = run_command(["jq", ".", str(path)], timeout=120)
    if result["returncode"] != 0:
        return result["stderr"] or "jq failed to format JSON"
    tmp_path.write_text(result["stdout"], encoding="utf-8")
    tmp_path.replace(path)
    return None


def scan_sbom(sbom_path: Path, json_output_path: Path, table_output_path: Path):
    target = f"sbom:{sbom_path}"
    result = run_command(["grype", target, "-o", f"json={json_output_path}", "-o", f"table={table_output_path}"], timeout=1800)
    if result["returncode"] != 0:
        return {"ok": False, "stage": "grype_sbom_scan", "returncode": result["returncode"], "stdout": result["stdout"], "stderr": result["stderr"]}
    format_error = pretty_json_file(json_output_path)
    if format_error:
        return {"ok": False, "stage": "grype_json_format", "returncode": 1, "stderr": format_error}
    return {"ok": True}
