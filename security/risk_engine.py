# AgentGuard - Risk Decision Engine


def make_decision(risk_score):
    """
    Convert a risk score into an AgentGuard security action.
    """

    if risk_score >= 80:
        return {
            "severity": "CRITICAL",
            "decision": "ISOLATE",
            "reason": "Critical risk detected. Agent should be isolated."
        }

    elif risk_score >= 60:
        return {
            "severity": "HIGH",
            "decision": "BLOCK",
            "reason": "High-risk activity detected. Action should be blocked."
        }

    elif risk_score >= 30:
        return {
            "severity": "MEDIUM",
            "decision": "REVIEW",
            "reason": "Suspicious activity detected. Human review required."
        }

    else:
        return {
            "severity": "LOW",
            "decision": "ALLOW",
            "reason": "Activity is within the expected risk range."
        }


if __name__ == "__main__":

    test_scores = [10, 45, 70, 90]

    for score in test_scores:

        result = make_decision(score)

        print("\n--------------------------")
        print("Risk Score:", score)
        print("Severity:", result["severity"])
        print("Decision:", result["decision"])
        print("Reason:", result["reason"])