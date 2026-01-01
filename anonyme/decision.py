def decide(findings: list, context: dict):
    risk = sum(f.confidence for f in findings)

    if risk >= 0.8:
        action = "BLOCK"
    elif risk >= 0.5:
        action = "REDACT"
    else:
        action = "ALLOW"

    return {
        "action": action,
        "risk_score": risk,
        "reasons": [f"{f.subtype} via {f.source}" for f in findings]
    }
