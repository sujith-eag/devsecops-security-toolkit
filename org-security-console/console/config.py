"""Application configuration loaded from environment variables."""

import os
from pathlib import Path


class Config:
    ORG_DATA_CURRENT_DIR = Path(os.environ.get("ORG_DATA_CURRENT_DIR", "/org-data/current"))
    REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/reports"))
    HOST = os.environ.get("CONSOLE_HOST", "0.0.0.0")
    PORT = int(os.environ.get("CONSOLE_PORT", "8080"))
