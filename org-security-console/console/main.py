"""Application factory and runtime entrypoint for org-security-console."""

from flask import Flask

from console.config import Config
from console.core.paths import ensure_dir
from console.data.store import DataStore
from console.services.queries import QueryService
from console.services.reports import ReportService
from console.web.routes import bp


def create_app():
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    app.config.from_object(Config)

    ensure_dir(app.config["REPORTS_DIR"])
    store = DataStore(app.config["ORG_DATA_CURRENT_DIR"])
    queries = QueryService(store)
    reports = ReportService(queries, app.config["REPORTS_DIR"])

    app.config["DATA_STORE"] = store
    app.config["QUERY_SERVICE"] = queries
    app.config["REPORT_SERVICE"] = reports
    app.register_blueprint(bp)
    return app


app = create_app()


if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=False)
