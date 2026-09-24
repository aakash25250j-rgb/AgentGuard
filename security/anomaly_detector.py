# AgentGuard - Behavioral Anomaly Detector

from sklearn.ensemble import IsolationForest


class BehaviorAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )

    def train(self, normal_activity):
        """
        Train the model using normal agent behavior.

        Each row:
        [api_calls, db_queries, files_accessed, data_mb]
        """
        self.model.fit(normal_activity)

    def predict(self, activity):
        """
        Return whether the current activity is anomalous.
        """
        prediction = self.model.predict([activity])[0]

        if prediction == -1:
            return {
                "anomaly": True,
                "risk_signal": 1,
                "reason": "Behavior deviates from normal agent activity"
            }

        return {
            "anomaly": False,
            "risk_signal": 0,
            "reason": "Behavior is within the learned normal pattern"
        }


if __name__ == "__main__":

    # Normal agent behavior
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

    detector = BehaviorAnomalyDetector()

    detector.train(normal_activity)

    # Normal activity
    normal_test = [10, 5, 12, 3]

    # Suspicious activity
    suspicious_test = [150, 200, 500, 800]

    print("Normal Activity:")
    print(detector.predict(normal_test))

    print("\nSuspicious Activity:")
    print(detector.predict(suspicious_test))