"""Flask routes for the local org security console."""

from flask import Blueprint, Response, current_app, redirect, render_template, request, url_for

bp = Blueprint("web", __name__)
DEFAULT_PER_PAGE = 250

def queries(): return current_app.config["QUERY_SERVICE"]
def reports(): return current_app.config["REPORT_SERVICE"]
def store(): return current_app.config["DATA_STORE"]

def paginated(items):
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", DEFAULT_PER_PAGE, type=int)
    page_data = queries().paginate(items, page, per_page)

    base_args = request.args.to_dict(flat=True)
    prev_args = dict(base_args, page=page_data["prev_page"], per_page=page_data["per_page"])
    next_args = dict(base_args, page=page_data["next_page"], per_page=page_data["per_page"])

    page_data["prev_args"] = prev_args
    page_data["next_args"] = next_args
    return page_data

@bp.route("/")
def overview(): return render_template("overview.html", overview=queries().overview(), title="Overview")

@bp.route("/remediation")
def remediation():
    return redirect(url_for("web.vulnerabilities", fix="fixable"))

@bp.route("/artifacts")
def artifacts():
    search = request.args.get("q", "")
    items = queries().artifacts(search or None)
    return render_template("artifacts.html", artifacts=paginated(items), page=paginated(items), search=search, title="Artifacts")

@bp.route("/artifact/<route_id>")
def artifact_detail(route_id): return render_template("artifact_detail.html", detail=queries().artifact_detail(route_id), title="Artifact Detail")

@bp.route("/vulnerabilities")
def vulnerabilities():
    severity = request.args.get("severity", "")
    fix = request.args.get("fix", "")
    search = request.args.get("q", "")
    package_type = request.args.get("type", "")

    action_view = queries().vulnerability_action_view(
        severity or None,
        fix or None,
        search or None,
        package_type or None,
    )

    all_rows = (
        action_view["fixable"]
        if fix == "fixable"
        else action_view["not_fixable"]
        if fix == "not-fixable"
        else action_view["all"]
    )

    page_data = paginated(all_rows)

    return render_template(
        "vulnerabilities.html",
        rows=page_data["items"],
        page=page_data,
        action_view=action_view,
        summary=queries().vulnerability_summary(
            queries().vulnerabilities(severity or None, fix or None, search or None)
        ),
        severity=severity,
        fix=fix,
        search=search,
        package_type=package_type,
        package_types=queries().package_types(),
        title="Vulnerabilities",
    )

@bp.route("/vulnerability/<route_id>")
def vulnerability_detail(route_id): return render_template("vulnerability_detail.html", detail=queries().vulnerability_detail(route_id), title="Vulnerability Detail")

@bp.route("/packages")
def packages():
    package_type = request.args.get("type", "")
    search = request.args.get("q", "")
    status = request.args.get("status", "")
    all_items = queries().packages(package_type or None, search or None, status or None)
    page_data = paginated(all_items)
    return render_template("packages.html", packages=page_data, page=page_data, package_types=queries().package_types(), package_type=package_type, search=search, status=status, title="Packages")

@bp.route("/package/<route_id>")
def package_detail(route_id): return render_template("package_detail.html", detail=queries().package_detail(route_id), title="Package Detail")

@bp.route("/data-health")
def data_health(): return render_template("data_health.html", health=queries().run_health(), title="Data Health")

@bp.route("/reports")
def report_page(): return render_template("reports.html", title="Reports")

@bp.route("/reports/download/<report_type>")
def download_report(report_type):
    target_id = request.args.get("target_id") or request.args.get("artifact_id")
    filename, content = reports().generate(report_type, target_id)
    return Response(content, mimetype="text/markdown", headers={"Content-Disposition": f"attachment; filename={filename}"})

@bp.route("/reports/write/<report_type>", methods=["POST", "GET"])
def write_report(report_type):
    target_id = request.values.get("target_id") or request.args.get("artifact_id")
    path = reports().write_report(report_type, target_id)
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