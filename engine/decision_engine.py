"""
Risk-Adaptive IAM Decision Engine
----------------------------------
Model  version : 0.2.0
Rule   version : 1.0.0

Architecture
------------
Decision = f(risk, business_rule, regulatory_constraint)

Zones
-----
  dynamic     — risk score drives the decision
  conditioned — risk + business rule
  restricted  — regulatory constraint dominates, risk cannot relax it
"""

from datetime import datetime, timezone
import json
import uuid

MODEL_VERSION = "0.2.0"
RULE_VERSION  = "1.0.0"


# ─── Risk scoring ─────────────────────────────────────────────────────────────

def calculate_risk(data: dict) -> tuple[int, list[dict]]:
    """
    Apply deterministic risk rules.
    Returns (total_score, list_of_activated_factors).
    """
    score   = 0
    factors = []

    if "Admin" in data.get("role", ""):
        score += 50
        factors.append({"rule": "R1", "reason": "privileged role", "score": 50})

    if not data.get("mfa_enabled", True):
        score += 40
        factors.append({"rule": "R2", "reason": "MFA disabled", "score": 40})

    inactive_days = data.get("last_login_days", 0)
    if inactive_days > 30:
        score += 20
        factors.append({
            "rule"  : "R3",
            "reason": f"inactive {inactive_days} days",
            "score" : 20,
        })

    if data.get("environment") == "production":
        score += 30
        factors.append({"rule": "R4", "reason": "production environment", "score": 30})

    return score, factors


def classify_risk(score: int) -> str:
    if score >= 100: return "CRITICAL"
    if score >= 50:  return "HIGH"
    if score >= 20:  return "MEDIUM"
    return "LOW"


# ─── Regulatory constraints ───────────────────────────────────────────────────

def check_regulatory_constraints(data: dict) -> list[dict]:
    """
    Hard constraints derived from regulatory frameworks.
    Violations cannot be overridden by risk score.
    """
    violations = []
    frameworks = data.get("framework", [])

    if not data.get("mfa_enabled", True):
        if "SOX" in frameworks:
            violations.append({
                "constraint": "C1",
                "framework" : "SOX",
                "reason"    : "MFA required for privileged access",
            })
        if "ISO27001" in frameworks:
            violations.append({
                "constraint": "C2",
                "framework" : "ISO27001",
                "reason"    : "strong authentication required for critical access",
            })

    return violations


# ─── Decision engine ──────────────────────────────────────────────────────────

def decide(data: dict) -> dict:
    """
    Core decision function.

    Produces a full decision trace — not just a verdict.
    Every output answers four questions:
      1. What happened?      → risk_score, risk_classification, decision
      2. Why did it happen?  → risk_factors, regulatory_violations
      3. Where did the decision come from? → decision_basis
      4. Which zone applied? → applied_zone
    """
    path = ["risk_scored"]

    risk_score, risk_factors   = calculate_risk(data)
    risk_classification        = classify_risk(risk_score)
    violations                 = check_regulatory_constraints(data)

    # Regulatory constraint takes precedence — cannot be relaxed by risk score
    if violations:
        path      += ["constraint_detected", "restricted_zone_applied", "decision_generated"]
        decision       = "BLOCK_OR_ENFORCE_MFA"
        decision_basis = "regulatory_constraint"
        applied_zone   = "restricted"

    elif risk_score >= 100:
        path      += ["critical_risk_detected", "conditioned_zone_applied", "decision_generated"]
        decision       = "REQUIRE_ACTION"
        decision_basis = "risk_score"
        applied_zone   = "conditioned"

    elif risk_score >= 50:
        path      += ["high_risk_detected", "dynamic_zone_applied", "decision_generated"]
        decision       = "ALLOW_WITH_RESTRICTION"
        decision_basis = "risk_score"
        applied_zone   = "dynamic"

    else:
        path      += ["low_risk_detected", "dynamic_zone_applied", "decision_generated"]
        decision       = "ALLOW"
        decision_basis = "risk_score"
        applied_zone   = "dynamic"

    return {
        "event_id"             : f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp"            : datetime.now(timezone.utc).isoformat(),
        "model_version"        : MODEL_VERSION,
        "rule_version"         : RULE_VERSION,
        "user"                 : data.get("user"),
        "target_resource"      : data.get("target_resource", "unspecified"),
        "environment"          : data.get("environment"),
        "framework_scope"      : data.get("framework", []),
        "risk_score"           : risk_score,
        "risk_classification"  : risk_classification,
        "risk_factors"         : risk_factors,
        "regulatory_violations": violations,
        "decision"             : decision,
        "decision_basis"       : decision_basis,
        "applied_zone"         : applied_zone,
        "decision_path"        : path,
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            input_data = json.load(f)
        print(json.dumps(decide(input_data), indent=2))
    else:
        print("Usage: python decision_engine.py <input.json>")
        print("       See examples/ for sample inputs.")
