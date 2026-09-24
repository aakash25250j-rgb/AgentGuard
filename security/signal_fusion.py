# AgentGuard - Signal Fusion Engine


SIGNAL_WEIGHTS = {
    "permission_violation": 20,
    "behavior_anomaly": 15,
    "sensitive_resource": 15,
    "unusual_data_volume": 15,
    "suspicious_sequence": 15,
    "intent_mismatch": 20
}


def calculate_risk(signals):
    """
    Combine multiple security signals and calculate
    an overall contextual risk score.
    """

    risk_score = 0
    triggered_signals = []

    for signal, weight in SIGNAL_WEIGHTS.items():

        if signals.get(signal, False):
            risk_score += weight
            triggered_signals.append(signal)

    # Keep score within 0-100
    risk_score = min(risk_score, 100)

    # Determine severity
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
        "triggered_signals": triggered_signals
    }