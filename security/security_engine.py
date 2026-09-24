# AgentGuard - Integrated Security Engine

from security.intent_analyzer import analyze_intent
from security.permission_checker import check_permission
from security.signal_fusion import calculate_risk
from security.risk_engine import make_decision
from security.anomaly_detector import BehaviorAnomalyDetector


# --------------------------------------------------
# 1. Resource sensitivity
# --------------------------------------------------

RESOURCE_SENSITIVITY = {
    "source_code": "LOW",
    "test_environment": "LOW",
    "reports": "MEDIUM",
    "analytics_database": "HIGH",
    "production_database": "CRITICAL",
    "production_credentials": "CRITICAL"
}


def is_sensitive_resource(resource):
    """
    Determine whether a resource is sensitive.
    """

    sensitivity = RESOURCE_SENSITIVITY.get(resource, "LOW")

    return sensitivity in ["HIGH", "CRITICAL"]


# --------------------------------------------------
# 2. Suspicious action sequence
# --------------------------------------------------

def detect_suspicious_sequence(actions):
    """
    Detect a suspicious sequence:

    SCAN
        ->
    ACCESS_SENSITIVE
        ->
    EXPORT_LARGE_DATA
    """

    suspicious_actions = {
        "SCAN",
        "ACCESS_SENSITIVE",
        "EXPORT_LARGE_DATA"
    }

    return suspicious_actions.issubset(set(actions))


# --------------------------------------------------
# 3. Agent behavior model
# --------------------------------------------------

normal_activity = [
    [10, 5, 12, 2],
    [12, 4, 15, 3],
    [8, 6, 10, 2],
    [11, 5, 13, 4],
    [9, 4, 11, 3],
    [13, 7, 14, 4],
    [10, 5, 12, 3],
    [9, 6, 13, 2],
    [12, 5, 15, 3],
    [11, 4, 10, 2]
]

behavior_detector = BehaviorAnomalyDetector()
behavior_detector.train(normal_activity)


# --------------------------------------------------
# 4. Evaluate one agent action
# --------------------------------------------------

def evaluate_agent_action(
    agent,
    task,
    action,
    resource,
    activity,
    action_history
):
    """
    Evaluate one AI-agent action using multiple
    security signals.
    """

    # ----------------------------------------------
    # Permission signal
    # ----------------------------------------------

    permission_result = check_permission(
        agent,
        action,
        resource
    )

    permission_violation = not permission_result["allowed"]

    # ----------------------------------------------
    # Intent signal
    # ----------------------------------------------

    intent_result = analyze_intent(
        task,
        action,
        resource
    )

    intent_mismatch = not intent_result["intent_match"]

    # ----------------------------------------------
    # Behavioral anomaly signal
    # ----------------------------------------------

    anomaly_result = behavior_detector.predict(activity)

    behavior_anomaly = anomaly_result["anomaly"]

    # ----------------------------------------------
    # Resource sensitivity signal
    # ----------------------------------------------

    sensitive_resource = is_sensitive_resource(resource)

    # ----------------------------------------------
    # Suspicious action sequence
    # ----------------------------------------------

    suspicious_sequence = detect_suspicious_sequence(
        action_history
    )

    # ----------------------------------------------
    # Unusual data volume
    # ----------------------------------------------

    # activity format:
    # [api_calls, db_queries, files_accessed, data_mb]

    unusual_data_volume = activity[3] > 100

    # ----------------------------------------------
    # Combine all security signals
    # ----------------------------------------------

    signals = {
        "permission_violation": permission_violation,
        "behavior_anomaly": behavior_anomaly,
        "sensitive_resource": sensitive_resource,
        "unusual_data_volume": unusual_data_volume,
        "suspicious_sequence": suspicious_sequence,
        "intent_mismatch": intent_mismatch
    }

    # ----------------------------------------------
    # Calculate risk
    # ----------------------------------------------

    risk_result = calculate_risk(signals)

    # ----------------------------------------------
    # Determine response
    # ----------------------------------------------

    decision_result = make_decision(
        risk_result["risk_score"]
    )

    # ----------------------------------------------
    # Final security result
    # ----------------------------------------------

    return {
        "agent": agent,
        "task": task,
        "action": action,
        "resource": resource,
        "permission": permission_result,
        "intent": intent_result,
        "signals": signals,
        "risk_score": risk_result["risk_score"],
        "severity": decision_result["severity"],
        "decision": decision_result["decision"],
        "reason": decision_result["reason"]
    }


# --------------------------------------------------
# 5. API-ready event evaluation
# --------------------------------------------------

def evaluate_event(event):
    """
    Evaluate an agent event received from the
    real-time AgentGuard gateway.
    """

    # ----------------------------------------------
    # Extract activity information
    # ----------------------------------------------

    activity = event["activity"]

    activity_vector = [
        activity["api_calls"],
        activity["db_queries"],
        activity["files_accessed"],
        activity["data_mb"]
    ]

    # ----------------------------------------------
    # Evaluate the event
    # ----------------------------------------------

    result = evaluate_agent_action(
        agent=event["agent"],
        task=event["task"],
        action=event["action"],
        resource=event["resource"],
        activity=activity_vector,
        action_history=event.get(
            "action_history",
            []
        )
    )

    # ----------------------------------------------
    # Return API-friendly response
    # ----------------------------------------------

    return {
        "agent": result["agent"],
        "task": result["task"],
        "action": result["action"],
        "resource": result["resource"],
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "decision": result["decision"],
        "signals": result["signals"],
        "permission": result["permission"],
        "intent": result["intent"],
        "reason": result["reason"]
    }


# --------------------------------------------------
# 6. Local live-event test
# --------------------------------------------------

if __name__ == "__main__":

    live_event = {
        "agent": "DevAgent",
        "task": "FIX_LOGIN",
        "action": "DELETE",
        "resource": "production_database",

        "activity": {
            "api_calls": 150,
            "db_queries": 200,
            "files_accessed": 500,
            "data_mb": 800
        },

        "action_history": [
            "SCAN",
            "ACCESS_SENSITIVE",
            "EXPORT_LARGE_DATA"
        ]
    }

    result = evaluate_event(live_event)

    print("\n==============================")
    print("AGENTGUARD SECURITY EVALUATION")
    print("==============================")

    print("Agent:", result["agent"])
    print("Task:", result["task"])
    print("Action:", result["action"])
    print("Resource:", result["resource"])

    print("\nRisk Score:", result["risk_score"])
    print("Severity:", result["severity"])
    print("Decision:", result["decision"])

    print("\nSecurity Signals:")

    for signal, triggered in result["signals"].items():
        print(f"  {signal}: {triggered}")

    print("\nReason:")
    print(result["reason"])