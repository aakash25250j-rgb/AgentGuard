# AgentGuard - Agent Behavior Fingerprint

from statistics import mean
import math


class AgentBehaviorFingerprint:

    def __init__(self, agent_name):
        self.agent_name = agent_name
        self.baseline = {}

    def learn_baseline(self, activity_records):
        """
        Learn the normal behavior baseline of an agent.

        Each record:
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
        Compare current activity with the learned baseline.
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
                deviations[label] = 0.0
                continue

            deviation = (
                abs(current_value - baseline_value)
                / baseline_value
            )

            deviations[label] = deviation

        average_deviation = mean(
            deviations.values()
        )

        # Convert deviation into a bounded 0-1 score.
        # This is a prototype heuristic, not a trained probability.
        deviation_score = 1 - math.exp(
            -average_deviation
        )

        return {
            "agent": self.agent_name,
            "baseline": self.baseline,
            "current_activity": activity,
            "deviations": deviations,
            "average_deviation": average_deviation,
            "deviation_score": round(
                deviation_score,
                4
            )
        }