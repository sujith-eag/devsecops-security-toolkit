"""Flask routes for the local org security console."""

from flask import Blueprint, Response, current_app, redirect, render_template, request, url_for

bp = Blueprint("web", __name__)

def queries(): return current_app.config["QUERY_SERVICE"]
def reports(): return current_app.config["REPORT_SERVICE"]
def store(): return current_app.config["DATA_STORE"]

@bp.route("/")
def overview():
    return render_template("overview.html", overview=queries().overview(), title="Overview")

@bp.route("/remediation")
def remediation():
    severity = request.args.get("severity", "")
    return render_template("remediation.html", items=queries().remediation_items(severity or None), severity=severity, title="Remediation")

@bp.route("/artifacts")
def artifacts():
    return render_template("artifacts.html", artifacts=queries().artifacts(), title="Artifacts")

@bp.route("/artifact/<path:artifact_id>")
def artifact_detail(artifact_id):
    return render_template("artifact_detail.html", detail=queries().artifact_detail(artifact_id), title="Artifact Detail")

@bp.route("/vulnerabilities")
def vulnerabilities():
    severity = request.args.get("severity", "")
    fix = request.args.get("fix", "")
    items = queries().vulnerabilities(severity or None, fix or None)
    return render_template("vulnerabilities.html", vulnerabilities=items, summary=queries().vulnerability_summary(items), severity=severity, fix=fix, title="Vulnerabilities")

@bp.route("/vulnerability/<path:vulnerability_id>")
def vulnerability_detail(vulnerability_id):
    return render_template("vulnerability_detail.html", detail=queries().vulnerability_detail(vulnerability_id), title="Vulnerability Detail")

@bp.route("/packages")
def packages():
    package_type = request.args.get("type", "")
    search = request.args.get("q", "")
    status = request.args.get("status", "")
    return render_template("packages.html", packages=queries().packages(package_type or None, search or None, status or None), package_types=queries().package_types(), package_type=package_type, search=search, status=status, title="Packages")

@bp.route("/package/<path:package_id>")
def package_detail(package_id):
    return render_template("package_detail.html", detail=queries().package_detail(package_id), title="Package Detail")

@bp.route("/reports")
def report_page():
    return render_template("reports.html", title="Reports")

@bp.route("/reports/download/<report_type>")
def download_report(report_type):
    artifact_id = request.args.get("artifact_id")
    filename, content = reports().generate(report_type, artifact_id)
    return Response(content, mimetype="text/markdown", headers={"Content-Disposition": f"attachment; filename={filename}"})

@bp.route("/reports/write/<report_type>", methods=["POST", "GET"])
def write_report(report_type):
    artifact_id = request.args.get("artifact_id")
    path = reports().write_report(report_type, artifact_id)
    return render_template("reports.html", title="Reports", message=f"Report written to {path}")

@bp.route("/health")
def health(): return {"status": "ok", "data_loaded": True}

@bp.route("/reload")
def reload_page():
    store().reload()
    return redirect(url_for("web.overview"))

@bp.route("/api/reload", methods=["POST"])
def api_reload():
    store().reload()
    return {"status": "reloaded"}
