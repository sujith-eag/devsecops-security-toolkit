"""Flask routes for the local org security console."""

from flask import Blueprint, Response, current_app, redirect, render_template, request, url_for

bp = Blueprint("web", __name__)


def queries():
    return current_app.config["QUERY_SERVICE"]


def reports():
    return current_app.config["REPORT_SERVICE"]


def store():
    return current_app.config["DATA_STORE"]


@bp.route("/")
def overview():
    return render_template("overview.html", overview=queries().overview(), title="Overview")


@bp.route("/remediation")
def remediation():
    return render_template("remediation.html", items=queries().remediation_items(), title="Remediation")


@bp.route("/artifacts")
def artifacts():
    return render_template("artifacts.html", artifacts=queries().artifacts(), title="Artifacts")


@bp.route("/artifact/<path:artifact_id>")
def artifact_detail(artifact_id):
    return render_template("artifact_detail.html", detail=queries().artifact_detail(artifact_id), title="Artifact Detail")


@bp.route("/vulnerabilities")
def vulnerabilities():
    return render_template("vulnerabilities.html", vulnerabilities=queries().vulnerabilities(), title="Vulnerabilities")


@bp.route("/vulnerability/<path:vulnerability_id>")
def vulnerability_detail(vulnerability_id):
    return render_template("vulnerability_detail.html", detail=queries().vulnerability_detail(vulnerability_id), title="Vulnerability Detail")


@bp.route("/packages")
def packages():
    package_type = request.args.get("type", "")
    items = queries().packages()
    if package_type:
        items = [item for item in items if item.get("package_type") == package_type]
    return render_template("packages.html", packages=items, package_type=package_type, title="Packages")


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
    return Response(
        content,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@bp.route("/reports/write/<report_type>", methods=["POST", "GET"])
def write_report(report_type):
    artifact_id = request.args.get("artifact_id")
    path = reports().write_report(report_type, artifact_id)
    return render_template("reports.html", title="Reports", message=f"Report written to {path}")


@bp.route("/health")
def health():
    return {"status": "ok", "data_loaded": True}


@bp.route("/reload")
def reload_page():
    store().reload()
    return redirect(url_for("web.overview"))


@bp.route("/api/reload", methods=["POST"])
def api_reload():
    store().reload()
    return {"status": "reloaded"}
