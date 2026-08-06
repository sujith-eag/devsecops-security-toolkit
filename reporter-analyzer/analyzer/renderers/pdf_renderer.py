"""PDF renderer using WeasyPrint."""

from pathlib import Path

from weasyprint import CSS, HTML

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
STYLESHEET = TEMPLATE_DIR / "styles.css"


def render_initial_pdf(html: str, output_path: str | Path) -> Path:
    """Convert rendered HTML into a PDF file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(
        path,
        stylesheets=[CSS(filename=str(STYLESHEET))],
    )
    return path
