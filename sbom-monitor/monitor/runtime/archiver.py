import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


def safe_timestamp(value: str) -> str:
    return value.replace(":", "-").replace("/", "-").replace(" ", "T")


def archive_current(monitoring_dir: Path):
    current_dir = monitoring_dir / "current"
    archive_dir = monitoring_dir / "archive"
    current_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)

    if not any(current_dir.iterdir()):
        return None

    previous_timestamp = None
    run_file = current_dir / "run" / "run-metadata.json"

    if run_file.is_file():
        try:
            data = json.loads(run_file.read_text(encoding="utf-8"))
            previous_timestamp = data.get("started_at") or data.get("run_id")
        except Exception:
            previous_timestamp = None

    if not previous_timestamp:
        previous_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    target = archive_dir / safe_timestamp(previous_timestamp)
    suffix = 1
    while target.exists():
        target = archive_dir / f"{safe_timestamp(previous_timestamp)}-{suffix}"
        suffix += 1

    target.mkdir(parents=True)
    for item in list(current_dir.iterdir()):
        shutil.move(str(item), str(target / item.name))

    return str(target)
