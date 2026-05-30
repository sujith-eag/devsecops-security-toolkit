import json
import os
import subprocess
from pathlib import Path


def run_command(args, timeout=None):
    completed = subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=os.environ.copy(),
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": args,
    }


def get_grype_version():
    result = run_command(["grype", "version", "-o", "json"], timeout=60)
    if result["returncode"] == 0:
        try:
            return json.loads(result["stdout"])
        except Exception:
            return {"raw": result["stdout"].strip()}
    fallback = run_command(["grype", "version"], timeout=60)
    return {"raw": fallback["stdout"].strip(), "error": fallback["stderr"].strip(), "returncode": fallback["returncode"]}


def update_grype_db():
    update_result = run_command(["grype", "db", "update"], timeout=600)
    status_result = run_command(["grype", "db", "status", "-o", "json"], timeout=120)

    status = None
    if status_result["returncode"] == 0:
        try:
            status = json.loads(status_result["stdout"])
        except Exception:
            status = {"raw": status_result["stdout"].strip()}
    else:
        status = {
            "raw": status_result["stdout"].strip(),
            "stderr": status_result["stderr"].strip(),
            "returncode": status_result["returncode"],
        }

    return {
        "update": {
            "returncode": update_result["returncode"],
            "stdout": update_result["stdout"].strip(),
            "stderr": update_result["stderr"].strip(),
        },
        "status": status,
    }


def pretty_json_file(path: Path):
    tmp_path = path.with_suffix(path.suffix + ".tmp")

    result = run_command(
        ["jq", ".", str(path)],
        timeout=120,
    )

    if result["returncode"] != 0:
        return result["stderr"] or "jq failed to format JSON"

    tmp_path.write_text(result["stdout"], encoding="utf-8")
    tmp_path.replace(path)

    return None


def scan_sbom(sbom_path: Path, json_output_path: Path, table_output_path: Path):
    target = f"sbom:{sbom_path}"

    result = run_command(
        [
            "grype",
            target,
            "-o",
            f"json={json_output_path}",
            "-o",
            f"table={table_output_path}",
        ],
        timeout=1800,
    )

    if result["returncode"] != 0:
        return {
            "ok": False,
            "stage": "grype_sbom_scan",
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
        }

    format_error = pretty_json_file(json_output_path)
    if format_error:
        return {
            "ok": False,
            "stage": "grype_json_format",
            "returncode": 1,
            "stdout": result["stdout"],
            "stderr": f"Failed to format Grype JSON output: {format_error}",
        }

    return {
        "ok": True,
        "table_returncode": 0,
        "table_stderr": "",
    }
