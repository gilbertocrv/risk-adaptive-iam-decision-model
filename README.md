# Risk-Adaptive IAM Decision Model

> Decision = f(risk, business_rule, regulatory_constraint)

A minimal, executable implementation of a risk-adaptive IAM decision architecture. The model makes access decisions dynamically — not through rigid workflows, but through deterministic rules applied to context, bounded by regulatory constraints, and traceable through structured evidence.

---

## The problem this solves

Most IAM implementations treat access control as a static configuration problem: role assigned, access granted. This model treats it as a **continuous decision problem**: every access event is evaluated against risk, business rules, and regulatory requirements — in real time.

---

## Architecture

```
[ Event / Trigger ]
        ↓
[ Context Collection ]
  user, role, MFA status, inactivity, environment
        ↓
[ Risk Scoring ]
  deterministic rules → score + classification
        ↓
[ Rule Engine ]
  ├─ Dynamic rules     (risk-based)
  └─ Hard constraints  (regulatory)
        ↓
[ Decision ]
  ├─ ALLOW
  ├─ ALLOW_WITH_RESTRICTION
  ├─ REQUIRE_ACTION
  └─ BLOCK_OR_ENFORCE_MFA
        ↓
[ Evidence Record ]
  full decision trace — auditable, versionable
```

### Decision zones

| Zone | Trigger | Decision driver |
|---|---|---|
| Dynamic | Low / high risk, no violations | Risk score |
| Conditioned | Critical risk, no violations | Risk score + business rule |
| Restricted | Regulatory violation detected | Constraint dominates — risk cannot relax it |

---

## Decision output

Every decision produces a full trace — not just a verdict.

```json
{
  "event_id": "evt-a3f1c9d20e4b",
  "timestamp": "2025-03-22T14:32:00Z",
  "model_version": "0.2.0",
  "rule_version": "1.0.0",
  "user": "admin01",
  "target_resource": "production-admin-portal",
  "environment": "production",
  "framework_scope": ["ISO27001", "SOX"],
  "risk_score": 140,
  "risk_classification": "CRITICAL",
  "risk_factors": [
    { "rule": "R1", "reason": "privileged role",       "score": 50 },
    { "rule": "R2", "reason": "MFA disabled",          "score": 40 },
    { "rule": "R3", "reason": "inactive 45 days",      "score": 20 },
    { "rule": "R4", "reason": "production environment","score": 30 }
  ],
  "regulatory_violations": [
    { "constraint": "C1", "framework": "SOX",      "reason": "MFA required for privileged access" },
    { "constraint": "C2", "framework": "ISO27001", "reason": "strong authentication required for critical access" }
  ],
  "decision": "BLOCK_OR_ENFORCE_MFA",
  "decision_basis": "regulatory_constraint",
  "applied_zone": "restricted",
  "decision_path": [
    "risk_scored",
    "constraint_detected",
    "restricted_zone_applied",
    "decision_generated"
  ]
}
```

The output answers four questions:

| Field | Question |
|---|---|
| `risk_score`, `decision` | What happened? |
| `risk_factors`, `regulatory_violations` | Why did it happen? |
| `decision_basis` | Where did the decision come from? |
| `applied_zone`, `decision_path` | Which part of the model applied? |

---

## Risk rules

| Rule | Condition | Score |
|---|---|---|
| R1 | Privileged role (contains "Admin") | +50 |
| R2 | MFA disabled | +40 |
| R3 | Inactivity > 30 days | +20 |
| R4 | Production environment | +30 |

## Regulatory constraints (hard limits)

| Constraint | Framework | Condition |
|---|---|---|
| C1 | SOX | MFA disabled + privileged access |
| C2 | ISO27001 | MFA disabled + critical access |

Regulatory constraints **cannot be overridden by risk score**. A low-risk user with a regulatory violation is blocked.

---

## Usage

```bash
# Run the engine with a JSON input
python engine/decision_engine.py examples/case1_restricted.json

# Run all tests
python tests/test_decision_engine.py
```

### Example inputs

| File | Zone | Expected decision |
|---|---|---|
| `case1_restricted.json` | Restricted | `BLOCK_OR_ENFORCE_MFA` |
| `case2_conditioned.json` | Dynamic | `ALLOW_WITH_RESTRICTION` |
| `case3_dynamic.json` | Dynamic | `ALLOW` |

---

## Repository structure

```
iam-decision-model/
├── engine/
│   └── decision_engine.py   # core logic
├── tests/
│   └── test_decision_engine.py
├── examples/
│   ├── case1_restricted.json
│   ├── case2_conditioned.json
│   └── case3_dynamic.json
├── docs/
│   └── architecture.md
└── README.md
```

---

## What this model does not do

- It does not define execution workflows
- It does not replace identity providers or access management platforms
- It does not handle authentication — only the access decision after authentication

The process guarantees data collection, consistency, and traceability. The logic lives in the rules and the risk calculation — not in the process itself.

---

## Compatibility

ISO 27001 · PCI DSS · SOX · LGPD

---

## Versioning

`model_version` and `rule_version` are embedded in every decision output. Changing a rule threshold requires bumping `rule_version`. This makes every historical decision traceable to the exact logic version that produced it.

---

## Next steps

- [ ] Question Engine / Hypothesis Layer — identify what the model does not yet know
- [ ] Maturity metrics aggregator — consume decision traces to measure rule stability
- [ ] Multi-event correlation — detect patterns across decisions for the same user
