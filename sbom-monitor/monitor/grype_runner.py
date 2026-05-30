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


def scan_sbom(sbom_path: Path, json_output_path: Path, table_output_path: Path):
    target = f"sbom:{sbom_path}"

    json_result = run_command(["grype", target, "-o", "json"], timeout=1800)
    if json_result["returncode"] != 0:
        return {
            "ok": False,
            "stage": "grype_json_scan",
            "returncode": json_result["returncode"],
            "stdout": json_result["stdout"],
            "stderr": json_result["stderr"],
        }

    json_output_path.write_text(json_result["stdout"], encoding="utf-8")

    table_result = run_command(["grype", target, "-o", "table"], timeout=1800)
    if table_result["returncode"] == 0:
        table_output_path.write_text(table_result["stdout"], encoding="utf-8")
    else:
        table_output_path.write_text(table_result["stdout"] + "\n" + table_result["stderr"], encoding="utf-8")

    return {
        "ok": True,
        "table_returncode": table_result["returncode"],
        "table_stderr": table_result["stderr"].strip(),
    }
