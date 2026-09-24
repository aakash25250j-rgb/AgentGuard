# AgentGuard - Contextual Signal Fusion

SIGNAL_WEIGHTS = {
    "permission_violation": 20,
    "behavior_anomaly": 15,
    "sensitive_resource": 15,
    "unusual_data_volume": 15,
    "suspicious_sequence": 15,
    "intent_mismatch": 20
}


def calculate_risk(signals, behavior_deviation_score=0.0):
    """
    Combine multiple security signals into a contextual
    risk score from 0 to 100.
    """

    risk_score = 0
    contributions = {}
    triggered_signals = []

    # Normal boolean signals
    for signal, weight in SIGNAL_WEIGHTS.items():

        if signal == "behavior_anomaly":
            continue

        triggered = bool(
            signals.get(signal, False)
        )

        contribution = weight if triggered else 0

        contributions[signal] = contribution
        risk_score += contribution

        if triggered:
            triggered_signals.append(signal)

    # Behavioral deviation contribution
    behavior_score = max(
        0.0,
        min(
            1.0,
            behavior_deviation_score
        )
    )

    behavior_contribution = round(
        SIGNAL_WEIGHTS["behavior_anomaly"]
        * behavior_score
    )

    contributions["behavior_anomaly"] = (
        behavior_contribution
    )

    if behavior_contribution > 0:
        triggered_signals.append(
            "behavior_anomaly"
        )

    risk_score += behavior_contribution

    risk_score = min(
        round(risk_score),
        100
    )

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "triggered_signals": triggered_signals,
        "contributions": contributions
    }