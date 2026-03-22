"""
Batch runner — Risk-Adaptive IAM Decision Engine
-------------------------------------------------
Runs multiple input cases, persists every decision, then
generates a maturity report from the accumulated evidence.

Usage
-----
  python run_batch.py                        # uses built-in test cases
  python run_batch.py examples/case1.json    # single file
  python run_batch.py examples/              # all JSON files in a directory
"""

import json
import sys
from pathlib import Path

# Allow imports from engine/
sys.path.insert(0, str(Path(__file__).parent / "engine"))

from decision_engine import decide
from persistence     import save, DEFAULT_DIR
from maturity        import build_report


# ─── Built-in cases ───────────────────────────────────────────────────────────
# Representative scenarios covering all three decision zones.

BUILTIN_CASES = [
    # ── Restricted zone ───────────────────────────────────────────────────────
    {
        "user": "admin01", "role": "Global Admin",
        "mfa_enabled": False, "last_login_days": 45,
        "environment": "production", "target_resource": "admin-portal",
        "framework": ["ISO27001", "SOX"],
    },
    {
        "user": "admin01", "role": "Global Admin",
        "mfa_enabled": False, "last_login_days": 50,
        "environment": "production", "target_resource": "billing-system",
        "framework": ["ISO27001", "SOX"],
    },
    {
        "user": "admin01", "role": "Global Admin",
        "mfa_enabled": False, "last_login_days": 55,
        "environment": "production", "target_resource": "user-directory",
        "framework": ["ISO27001", "SOX"],
    },
    # ── Conditioned zone ──────────────────────────────────────────────────────
    {
        "user": "dba_senior", "role": "DB Admin",
        "mfa_enabled": True, "last_login_days": 35,
        "environment": "production", "target_resource": "db-cluster-prod",
        "framework": [],
    },
    {
        "user": "dba_senior", "role": "DB Admin",
        "mfa_enabled": True, "last_login_days": 38,
        "environment": "production", "target_resource": "db-replica-prod",
        "framework": [],
    },
    # ── Dynamic zone — allow with restriction ─────────────────────────────────
    {
        "user": "dba02", "role": "DB Admin",
        "mfa_enabled": True, "last_login_days": 10,
        "environment": "production", "target_resource": "db-cluster-prod",
        "framework": ["ISO27001"],
    },
    {
        "user": "eng01", "role": "Read Admin",
        "mfa_enabled": True, "last_login_days": 8,
        "environment": "production", "target_resource": "logs-portal",
        "framework": ["ISO27001"],
    },
    # ── Dynamic zone — allow ──────────────────────────────────────────────────
    {
        "user": "user99", "role": "Viewer",
        "mfa_enabled": True, "last_login_days": 5,
        "environment": "staging", "target_resource": "reports-dashboard",
        "framework": ["ISO27001"],
    },
    {
        "user": "user42", "role": "Viewer",
        "mfa_enabled": True, "last_login_days": 3,
        "environment": "staging", "target_resource": "analytics-dashboard",
        "framework": ["ISO27001"],
    },
    {
        "user": "analyst01", "role": "Analyst",
        "mfa_enabled": True, "last_login_days": 1,
        "environment": "staging", "target_resource": "data-exports",
        "framework": ["ISO27001"],
    },
]


# ─── Runner ───────────────────────────────────────────────────────────────────

def load_cases_from_path(path: Path) -> list[dict]:
    cases = []
    targets = [path] if path.is_file() else sorted(path.glob("*.json"))
    for f in targets:
        with open(f) as fp:
            data = json.load(fp)
        data.pop("_description", None)
        cases.append(data)
    return cases


def run_batch(cases: list[dict], evidence_dir=DEFAULT_DIR) -> list[dict]:
    results = []
    for case in cases:
        record = decide(case)
        log_file = save(record, evidence_dir)
        results.append(record)
        print(f"  [{record['decision']:<28}]  {record['user']}  →  {log_file.name}")
    return results


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    evidence_dir = DEFAULT_DIR

    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
        cases  = load_cases_from_path(target)
    else:
        cases = BUILTIN_CASES

    print(f"\nBatch runner — {len(cases)} cases\n{'─' * 52}")
    results = run_batch(cases, evidence_dir)

    print(f"\n{'─' * 52}")
    print(f"  Decisions saved to: {evidence_dir}/\n")

    print("Maturity report\n" + "─" * 52)
    report = build_report(evidence_dir)
    print(json.dumps(report, indent=2))
