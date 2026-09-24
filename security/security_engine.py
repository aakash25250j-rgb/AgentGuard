# AgentGuard - Integrated Security Engine
from security.action_sequence import detect_suspicious_sequence
from security.intent_analyzer import analyze_intent
from security.permission_checker import check_permission
from security.signal_fusion import calculate_risk
from security.risk_engine import make_decision
from security.anomaly_detector import BehaviorAnomalyDetector
from security.behavior_fingerprint import AgentBehaviorFingerprint
from security.action_sequence import detect_suspicious_sequence


# --------------------------------------------------
# Resource sensitivity
# --------------------------------------------------

RESOURCE_SENSITIVITY = {
    "source_code": "LOW",
    "test_environment": "LOW",
    "reports": "MEDIUM",
    "analytics_database": "HIGH",
    "production_database": "CRITICAL",
    "production_credentials": "CRITICAL"
}


def get_resource_sensitivity(resource):
    return RESOURCE_SENSITIVITY.get(
        resource,
        "LOW"
    )


def is_sensitive_resource(resource):
    return get_resource_sensitivity(
        resource
    ) in ["HIGH", "CRITICAL"]


# --------------------------------------------------
# Baseline behavior
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


# ML detector
behavior_detector = BehaviorAnomalyDetector()
behavior_detector.train(
    normal_activity
)


# Explainable behavior fingerprint
behavior_fingerprint = AgentBehaviorFingerprint(
    "DevAgent"
)

behavior_fingerprint.learn_baseline(
    normal_activity
)


# --------------------------------------------------
# Evaluate one agent action
# --------------------------------------------------

def evaluate_agent_action(
    agent,
    task,
    action,
    resource,
    activity,
    action_history
):

    # Permission
    permission_result = check_permission(
        agent,
        action,
        resource
    )

    permission_violation = not (
        permission_result["allowed"]
    )

    # Intent
    intent_result = analyze_intent(
        task,
        action,
        resource
    )

    intent_mismatch = not (
        intent_result["intent_match"]
    )

    # ML anomaly
    anomaly_result = behavior_detector.predict(
        activity
    )

    behavior_anomaly = anomaly_result[
        "anomaly"
    ]

    # Behavior fingerprint
    fingerprint_result = behavior_fingerprint.compare(
        activity
    )

    deviation_score = fingerprint_result[
        "deviation_score"
    ]

    # Resource
    sensitive_resource = is_sensitive_resource(
        resource
    )

    # Sequence
    suspicious_sequence = detect_suspicious_sequence(
        action_history
    )

    # Data volume
    unusual_data_volume = (
        activity[3] > 100
    )

    # Signals
    signals = {
        "permission_violation": permission_violation,
        "behavior_anomaly": behavior_anomaly,
        "sensitive_resource": sensitive_resource,
        "unusual_data_volume": unusual_data_volume,
        "suspicious_sequence": suspicious_sequence,
        "intent_mismatch": intent_mismatch
    }

    # Fusion
    risk_result = calculate_risk(
        signals,
        behavior_deviation_score=deviation_score
    )

    # Decision
    decision_result = make_decision(
        risk_result["risk_score"]
    )

    return {
        "agent": agent,
        "task": task,
        "action": action,
        "resource": resource,
        "resource_sensitivity":
            get_resource_sensitivity(resource),

        "permission": permission_result,
        "intent": intent_result,

        "behavior": {
            "ml_anomaly": behavior_anomaly,
            "deviation_score":
                deviation_score,
            "average_deviation":
                fingerprint_result[
                    "average_deviation"
                ],
            "deviations":
                fingerprint_result[
                    "deviations"
                ]
        },

        "signals": signals,

        "risk": {
            "score":
                risk_result[
                    "risk_score"
                ],
            "severity":
                risk_result[
                    "severity"
                ],
            "contributions":
                risk_result[
                    "contributions"
                ]
        },

        "decision":
            decision_result[
                "decision"
            ],

        "reason":
            decision_result[
                "reason"
            ]
    }


# --------------------------------------------------
# API-ready event evaluation
# --------------------------------------------------

def evaluate_event(event):

    required_fields = [
        "agent",
        "task",
        "action",
        "resource",
        "activity"
    ]

    missing = [
        field
        for field in required_fields
        if field not in event
    ]

    if missing:
        raise ValueError(
            f"Missing required fields: {missing}"
        )

    activity = event["activity"]

    activity_vector = [
        activity["api_calls"],
        activity["db_queries"],
        activity["files_accessed"],
        activity["data_mb"]
    ]

    return evaluate_agent_action(
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


# --------------------------------------------------
# Local test
# --------------------------------------------------

if __name__ == "__main__":

    test_event = {
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

    result = evaluate_event(
        test_event
    )

    print("\nAgentGuard Security Evaluation")
    print("--------------------------------")

    print("Agent:",
          result["agent"])

    print("Action:",
          result["action"])

    print("Resource:",
          result["resource"])

    print(
        "Resource Sensitivity:",
        result[
            "resource_sensitivity"
        ]
    )

    print(
        "Risk Score:",
        result[
            "risk"
        ]["score"]
    )

    print(
        "Severity:",
        result[
            "risk"
        ]["severity"]
    )

    print(
        "Decision:",
        result["decision"]
    )

    print("\nSignals:")

    for name, value in result[
        "signals"
    ].items():

        print(
            f"  {name}: {value}"
        )

    print("\nBehavior:")
    print(
        "  ML anomaly:",
        result[
            "behavior"
        ]["ml_anomaly"]
    )

    print(
        "  Deviation score:",
        result[
            "behavior"
        ]["deviation_score"]
    )