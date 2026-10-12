from collections import defaultdict
from datetime import datetime, timedelta


class BehaviorAnalyzer:
    """
    Detects abnormal traffic behavior using time-window snapshots.

    Each source IP gets a behavioral baseline built from
    completed time-window samples.

    A new window is considered anomalous when one or more
    metrics significantly exceed the learned baseline.
    """

    def __init__(
        self,
        time_window_seconds: int = 10,
        minimum_samples: int = 5,
        deviation_multiplier: float = 3.0,
    ):
        if time_window_seconds <= 0:
            raise ValueError(
                "time_window_seconds must be greater than 0."
            )

        if minimum_samples <= 0:
            raise ValueError(
                "minimum_samples must be greater than 0."
            )

        if deviation_multiplier <= 0:
            raise ValueError(
                "deviation_multiplier must be greater than 0."
            )

        self.time_window = timedelta(
            seconds=time_window_seconds
        )

        self.minimum_samples = minimum_samples
        self.deviation_multiplier = deviation_multiplier

        self.current_windows = {}
        self.history = defaultdict(list)

    def _window_start(self, timestamp: datetime) -> datetime:
        """
        Calculate the beginning of the current time window.
        """

        seconds = int(timestamp.timestamp())

        window_seconds = int(
            self.time_window.total_seconds()
        )

        window_start_seconds = (
            seconds // window_seconds
        ) * window_seconds

        return datetime.fromtimestamp(
            window_start_seconds,
            tz=timestamp.tzinfo,
        )

    def _calculate_baseline(self, source_ip: str):
        """
        Calculate the average behavior from previous
        completed windows.
        """

        samples = self.history[source_ip]

        if len(samples) < self.minimum_samples:
            return None

        return {
            "average_connection_rate": sum(
                sample["connection_rate"]
                for sample in samples
            ) / len(samples),

            "average_unique_ports": sum(
                sample["unique_ports"]
                for sample in samples
            ) / len(samples),

            "average_unique_hosts": sum(
                sample["unique_hosts"]
                for sample in samples
            ) / len(samples),
        }

    def _analyze_window(
        self,
        source_ip: str,
        window_start: datetime,
        metrics: dict,
    ):
        """
        Compare a completed window against the learned baseline.
        """

        baseline = self._calculate_baseline(source_ip)

        # Always add the completed window to history.
        self.history[source_ip].append(metrics)

        if baseline is None:
            return None

        anomalies = []

        baseline_rate = baseline["average_connection_rate"]

        if (
            baseline_rate > 0
            and metrics["connection_rate"]
            >= baseline_rate * self.deviation_multiplier
        ):
            anomalies.append("CONNECTION_RATE_ANOMALY")

        baseline_ports = baseline["average_unique_ports"]

        if (
            baseline_ports > 0
            and metrics["unique_ports"]
            >= baseline_ports * self.deviation_multiplier
        ):
            anomalies.append("PORT_BEHAVIOR_ANOMALY")

        baseline_hosts = baseline["average_unique_hosts"]

        if (
            baseline_hosts > 0
            and metrics["unique_hosts"]
            >= baseline_hosts * self.deviation_multiplier
        ):
            anomalies.append("HOST_BEHAVIOR_ANOMALY")

        if not anomalies:
            return None

        return {
            "alert_type": "BEHAVIOR_ANOMALY",
            "source_ip": source_ip,
            "window_start": window_start.isoformat(),
            "anomalies": anomalies,
            "connection_rate": metrics["connection_rate"],
            "unique_ports": metrics["unique_ports"],
            "unique_hosts": metrics["unique_hosts"],
            "baseline": baseline,
        }

    def process(
        self,
        source_ip: str,
        connection_rate: float,
        unique_ports: int,
        unique_hosts: int,
        timestamp: datetime | None = None,
    ):
        """
        Process the current behavioral observation.

        Observations belonging to the same time window are
        accumulated together.

        Analysis happens only when a new time window starts.
        """

        if timestamp is None:
            timestamp = datetime.now().astimezone()

        window_start = self._window_start(timestamp)

        current = self.current_windows.get(source_ip)

        current_metrics = {
            "connection_rate": connection_rate,
            "unique_ports": unique_ports,
            "unique_hosts": unique_hosts,
        }

        # First observation for this source.
        if current is None:
            self.current_windows[source_ip] = {
                "window_start": window_start,
                "metrics": current_metrics,
            }

            return None

        # Still inside the same window.
        if current["window_start"] == window_start:
            current["metrics"] = current_metrics
            return None

        # A new window started.
        previous_window_start = current["window_start"]
        previous_metrics = current["metrics"]

        alert = self._analyze_window(
            source_ip=source_ip,
            window_start=previous_window_start,
            metrics=previous_metrics,
        )

        # Start the new window.
        self.current_windows[source_ip] = {
            "window_start": window_start,
            "metrics": current_metrics,
        }

        return alert