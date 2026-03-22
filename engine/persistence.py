"""
Persistence layer — Risk-Adaptive IAM Decision Engine
------------------------------------------------------
Saves every decision record to a structured JSONL log.
One decision per line — append-only, easy to stream and parse.

Format: evidence/<YYYY-MM-DD>.jsonl
Each line: one complete decision trace (JSON).
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DIR = Path(__file__).parent.parent / "evidence"


def save(record: dict, evidence_dir: Path = DEFAULT_DIR) -> Path:
    """
    Append a decision record to the daily JSONL evidence file.
    Returns the path of the file written to.
    """
    evidence_dir.mkdir(parents=True, exist_ok=True)

    date_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file  = evidence_dir / f"{date_str}.jsonl"

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return log_file


def load_all(evidence_dir: Path = DEFAULT_DIR) -> list[dict]:
    """
    Load every decision record from all JSONL files in evidence_dir.
    Returns a flat list sorted by timestamp ascending.
    """
    records = []

    for jsonl_file in sorted(evidence_dir.glob("*.jsonl")):
        with open(jsonl_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

    records.sort(key=lambda r: r.get("timestamp", ""))
    return records


def load_by_user(user: str, evidence_dir: Path = DEFAULT_DIR) -> list[dict]:
    """Return all records for a specific user."""
    return [r for r in load_all(evidence_dir) if r.get("user") == user]
