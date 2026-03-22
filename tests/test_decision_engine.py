"""
Test suite — Risk-Adaptive IAM Decision Engine
Covers all three decision zones and edge cases.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'engine'))

from decision_engine import decide, calculate_risk, check_regulatory_constraints


# ─── Helpers ──────────────────────────────────────────────────────────────────

def run(label, case, checks):
    result = decide(case)
    passed = all(result.get(k) == v for k, v in checks.items())
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {label}")
    if not passed:
        for k, v in checks.items():
            if result.get(k) != v:
                print(f"         {k}: expected={v!r}  got={result.get(k)!r}")
    return passed


# ─── Test cases ───────────────────────────────────────────────────────────────

def test_restricted_zone_regulatory_constraint():
    """Privileged admin, no MFA, SOX scope → restricted zone, regulatory constraint."""
    return run(
        "Restricted zone — regulatory constraint (SOX + ISO27001)",
        {
            "user"            : "admin01",
            "role"            : "Global Admin",
            "mfa_enabled"     : False,
            "last_login_days" : 45,
            "environment"     : "production",
            "target_resource" : "production-admin-portal",
            "framework"       : ["ISO27001", "SOX"],
        },
        {
            "decision"       : "BLOCK_OR_ENFORCE_MFA",
            "decision_basis" : "regulatory_constraint",
            "applied_zone"   : "restricted",
            "risk_score"     : 140,
            "risk_classification": "CRITICAL",
        }
    )


def test_conditioned_zone_critical_risk():
    """High risk score, no regulatory violation → conditioned zone."""
    return run(
        "Conditioned zone — critical risk, no regulatory violation",
        {
            "user"            : "dba_senior",
            "role"            : "DB Admin",
            "mfa_enabled"     : True,
            "last_login_days" : 35,
            "environment"     : "production",
            "target_resource" : "db-cluster-prod",
            "framework"       : [],
        },
        {
            "decision"       : "REQUIRE_ACTION",
            "decision_basis" : "risk_score",
            "applied_zone"   : "conditioned",
            "risk_score"     : 100,
            "risk_classification": "CRITICAL",
        }
    )


def test_dynamic_zone_high_risk_with_restriction():
    """Privileged + production but MFA active, no violations → dynamic zone with restriction."""
    return run(
        "Dynamic zone — high risk, MFA active, no regulatory violation",
        {
            "user"            : "dba02",
            "role"            : "DB Admin",
            "mfa_enabled"     : True,
            "last_login_days" : 10,
            "environment"     : "production",
            "target_resource" : "db-cluster-prod",
            "framework"       : ["ISO27001"],
        },
        {
            "decision"       : "ALLOW_WITH_RESTRICTION",
            "decision_basis" : "risk_score",
            "applied_zone"   : "dynamic",
            "risk_score"     : 80,
        }
    )


def test_dynamic_zone_allow():
    """Standard user, low risk, MFA active → allow."""
    return run(
        "Dynamic zone — low risk, allow",
        {
            "user"            : "user99",
            "role"            : "Viewer",
            "mfa_enabled"     : True,
            "last_login_days" : 5,
            "environment"     : "staging",
            "target_resource" : "reports-dashboard",
            "framework"       : ["ISO27001"],
        },
        {
            "decision"       : "ALLOW",
            "decision_basis" : "risk_score",
            "applied_zone"   : "dynamic",
            "risk_score"     : 0,
            "risk_classification": "LOW",
        }
    )


def test_regulatory_overrides_low_risk():
    """Even with low behavioral risk, a regulatory violation must block."""
    return run(
        "Regulatory constraint overrides low risk",
        {
            "user"            : "readonly_admin",
            "role"            : "Read Admin",
            "mfa_enabled"     : False,
            "last_login_days" : 2,
            "environment"     : "staging",
            "target_resource" : "logs-portal",
            "framework"       : ["SOX"],
        },
        {
            "decision"       : "BLOCK_OR_ENFORCE_MFA",
            "decision_basis" : "regulatory_constraint",
            "applied_zone"   : "restricted",
        }
    )


def test_decision_path_structure():
    """Decision path must always start with risk_scored and end with decision_generated."""
    result = decide({
        "user": "x", "role": "Viewer", "mfa_enabled": True,
        "last_login_days": 1, "environment": "dev", "framework": []
    })
    path = result.get("decision_path", [])
    assert path[0] == "risk_scored",        "path must start with risk_scored"
    assert path[-1] == "decision_generated", "path must end with decision_generated"
    print("  [PASS] Decision path structure")
    return True


def test_output_fields_complete():
    """All required fields must be present in every output."""
    required = [
        "event_id", "timestamp", "model_version", "rule_version",
        "user", "target_resource", "environment", "framework_scope",
        "risk_score", "risk_classification", "risk_factors",
        "regulatory_violations", "decision", "decision_basis",
        "applied_zone", "decision_path",
    ]
    result = decide({
        "user": "x", "role": "Viewer", "mfa_enabled": True,
        "last_login_days": 1, "environment": "dev", "framework": []
    })
    missing = [f for f in required if f not in result]
    if missing:
        print(f"  [FAIL] Output completeness — missing: {missing}")
        return False
    print("  [PASS] Output completeness — all required fields present")
    return True


# ─── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_restricted_zone_regulatory_constraint,
        test_conditioned_zone_critical_risk,
        test_dynamic_zone_high_risk_with_restriction,
        test_dynamic_zone_allow,
        test_regulatory_overrides_low_risk,
        test_decision_path_structure,
        test_output_fields_complete,
    ]

    print("\nRisk-Adaptive IAM Decision Engine — Test Suite")
    print("=" * 52)

    results = [t() for t in tests]
    total   = len(results)
    passed  = sum(results)

    print("─" * 52)
    print(f"  {passed}/{total} passed\n")
    sys.exit(0 if passed == total else 1)
