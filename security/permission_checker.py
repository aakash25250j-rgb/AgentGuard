# AgentGuard - Permission Checker

# Example permissions for our simulated AI agents
AGENT_PERMISSIONS = {
    "DevAgent": {
        "source_code": ["READ", "WRITE"],
        "test_environment": ["READ", "WRITE", "EXECUTE"],
        "production_database": ["READ"]
    },

    "DataAgent": {
        "analytics_database": ["READ", "QUERY"],
        "reports": ["READ", "WRITE"]
    }
}


def check_permission(agent, action, resource):
    """
    Check whether an AI agent is allowed
    to perform an action on a resource.
    """

    # Check whether the agent exists
    if agent not in AGENT_PERMISSIONS:
        return {
            "allowed": False,
            "reason": "Unknown agent"
        }

    agent_permissions = AGENT_PERMISSIONS[agent]

    # Check whether the resource exists
    if resource not in agent_permissions:
        return {
            "allowed": False,
            "reason": "Resource not permitted for this agent"
        }

    # Check whether the action is allowed
    if action in agent_permissions[resource]:
        return {
            "allowed": True,
            "reason": "Permission granted"
        }

    return {
        "allowed": False,
        "reason": "Action not permitted"
    }


if __name__ == "__main__":
    print(check_permission(
        "DevAgent",
        "READ",
        "source_code"
    ))

    print(check_permission(
        "DevAgent",
        "DELETE",
        "production_database"
    ))