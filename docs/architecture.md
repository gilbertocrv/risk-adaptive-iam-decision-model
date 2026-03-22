# Architecture — Risk-Adaptive IAM Decision Model

## Central formulation

> The model operates real-time decisions based on risk, within regulatory limits, using maturity as a continuous feedback mechanism to guarantee consistency and control over time.

---

## Core principle

The system does not need to know all the answers.  
It needs to know which questions to ask, when to ask them, and how to respond based on risk.

---

## Decision formula

```
Decision = f(risk, business_rule, regulatory_constraint)
```

---

## Decision zones

### Dynamic zone
Risk score drives the decision.  
Low or moderate risk → access allowed or allowed with restriction.  
No regulatory violation present.

### Conditioned zone
Critical risk score + business rule.  
Risk is high enough that additional action is required, even without a regulatory violation.

### Restricted zone
Regulatory constraint dominates.  
The risk score cannot relax the decision.  
A user with score 0 who violates a regulatory constraint is still blocked.

---

## Layer 1 — Real-time decision

```
[ Event / Trigger ]
        ↓
[ Context Collection ]
  (user, access, behavior, criticality)
        ↓
[ Risk Calculation ]
  (score + classification)
        ↓
[ Rule Engine ]
  ├─ Dynamic rules   (risk-based)
  └─ Hard constraints (framework/regulatory)
        ↓
[ Decision ]
  ├─ ALLOW
  ├─ ALLOW_WITH_RESTRICTION
  ├─ REQUIRE_ACTION
  └─ BLOCK_OR_ENFORCE_MFA
        ↓
[ Evidence Record ]
  (log, rule applied, risk, decision, timestamp)
```

---

## Layer 2 — Regulatory limits

Frameworks do not define execution.  
They delimit acceptable risk, impose constraints, and standardize criteria.

```
[ Frameworks / Regulation ]
  (ISO 27001, PCI DSS, SOX, LGPD)
        ↓
[ Non-Negotiable Rules ]
  (MFA mandatory, formal approval mandatory)
        ↓
[ Decision Space Boundary ]
  → prevents improper relaxation
```

---

## Layer 3 — Maturity (accumulated time)

Maturity does not measure process execution.  
It measures decision consistency, risk adherence, and model stability.

```
[ Decision History ]
        ↓
[ Metrics ]
  ├─ % risk outside tolerance
  ├─ exception frequency
  ├─ regulatory violations
  └─ decision response time
        ↓
[ Maturity State ]
  ├─ Stable   (risk controlled)
  ├─ Unstable (high variance)
  └─ Critical (outside tolerance)
        ↓
[ Model Adjustment ]
  ├─ threshold tuning
  ├─ rule revision
  └─ control reinforcement
```

---

## Feedback loop

```
Decision (real-time)
        ↓
Result / Impact
        ↓
Metrics
        ↓
Maturity
        ↓
Rule adjustment
        ↓
Next decision (better calibrated)
```

---

## Role of process

Process does not define decision logic.  
It guarantees:
- data collection
- consistency
- traceability
- evidence

---

## Applicability

The model is valid when:
- reliable context data exists
- rules are deterministic
- decisions are well-defined per risk zone
- evidence is recorded for every decision

Compatible with: ISO 27001 · PCI DSS · SOX · LGPD

---

## Evolution path

### Question Engine / Hypothesis Layer (next version)

The model as built answers: given this context, what is the decision?

The next layer answers: what do we not yet know? What needs to be validated? Where can risk emerge without a current signal?

This transforms the model from a decision engine into an investigation engine — where absence of data is itself a signal, not silence.

```
Current:    context → risk → decision
Next:       context + gaps → hypothesis → investigation → risk → decision
```
