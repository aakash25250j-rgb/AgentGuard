# AgentGuard - Intent Analyzer


TASK_POLICIES = {

    "FIX_LOGIN": {
        "allowed_actions": {
            "READ",
            "WRITE",
            "EXECUTE"
        },
        "allowed_resources": {
            "source_code",
            "test_environment"
        }
    },

    "ANALYZE_DATA": {
        "allowed_actions": {
            "READ",
            "QUERY"
        },
        "allowed_resources": {
            "analytics_database",
            "reports"
        }
    }
}


def analyze_intent(task, action, resource):
    """
    Determine whether the current action is consistent
    with the agent's assigned task.
    """

    policy = TASK_POLICIES.get(task)

    if policy is None:
        return {
            "intent_match": False,
            "reason": "Unknown task"
        }

    action_allowed = action in policy["allowed_actions"]
    resource_allowed = resource in policy["allowed_resources"]

    if action_allowed and resource_allowed:
        return {
            "intent_match": True,
            "reason": "Action is consistent with assigned task"
        }

    return {
        "intent_match": False,
        "reason": "Action does not match assigned task"
    }

if __name__ == "__main__":

    result1 = analyze_intent(
        "FIX_LOGIN",
        "WRITE",
        "source_code"
    )

    result2 = analyze_intent(
        "FIX_LOGIN",
        "DELETE",
        "production_database"
    )

    print("Normal Intent:")
    print(result1)

    print("\nSuspicious Intent:")
    print(result2)