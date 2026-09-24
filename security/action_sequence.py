# AgentGuard - Action Sequence Detector

SUSPICIOUS_PATTERN = [
    "SCAN",
    "ACCESS_SENSITIVE",
    "EXPORT_LARGE_DATA"
]


def detect_suspicious_sequence(actions):
    """
    Detect whether the suspicious actions occur
    in the expected order.

    They do not have to be consecutive.
    """

    pattern_index = 0

    for action in actions:
        if action == SUSPICIOUS_PATTERN[pattern_index]:
            pattern_index += 1

            if pattern_index == len(SUSPICIOUS_PATTERN):
                return True

    return False