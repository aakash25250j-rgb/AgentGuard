# AgentGuard - Agent Behavior Fingerprint

from statistics import mean


class AgentBehaviorFingerprint:

    def __init__(self, agent_name):
        self.agent_name = agent_name
        self.baseline = {}

    def learn_baseline(self, activity_records):
        """
        Learn the average behavior of an agent.

        Each activity record:
        [api_calls, db_queries, files_accessed, data_mb]
        """

        if not activity_records:
            raise ValueError("No activity records provided.")

        self.baseline = {
            "api_calls": mean(
                record[0] for record in activity_records
            ),
            "db_queries": mean(
                record[1] for record in activity_records
            ),
            "files_accessed": mean(
                record[2] for record in activity_records
            ),
            "data_mb": mean(
                record[3] for record in activity_records
            )
        }

    def compare(self, activity):
        """
        Compare current activity against the learned baseline.
        """

        if not self.baseline:
            raise ValueError("Baseline has not been trained.")

        labels = [
            "api_calls",
            "db_queries",
            "files_accessed",
            "data_mb"
        ]

        deviations = {}

        for index, label in enumerate(labels):

            baseline_value = self.baseline[label]

            current_value = activity[index]

            if baseline_value == 0:
                deviations[label] = 0
                continue

            deviation = abs(
                current_value - baseline_value
            ) / baseline_value

            deviations[label] = deviation

        average_deviation = mean(
            deviations.values()
        )

        return {
            "agent": self.agent_name,
            "baseline": self.baseline,
            "current_activity": activity,
            "deviations": deviations,
            "average_deviation": average_deviation
        }


if __name__ == "__main__":

    normal_activity = [
        [10, 5, 12, 2],
        [12, 4, 15, 3],
        [8, 6, 10, 2],
        [11, 5, 13, 4],
        [9, 4, 11, 3]
    ]

    fingerprint = AgentBehaviorFingerprint(
        "DevAgent"
    )

    fingerprint.learn_baseline(
        normal_activity
    )

    normal_test = [10, 5, 12, 3]

    suspicious_test = [150, 200, 500, 800]

    print("\nNORMAL BEHAVIOR")
    print(
        fingerprint.compare(normal_test)
    )

    print("\nSUSPICIOUS BEHAVIOR")
    print(
        fingerprint.compare(suspicious_test)
    )