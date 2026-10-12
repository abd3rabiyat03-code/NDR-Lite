from collections import defaultdict
from datetime import timedelta


class TrafficMetrics:
    """
    Calculates traffic behavior metrics for each source IP.

    Supported metrics:
    - Connection rate
    - Failed connection ratio
    - Unique destination ports
    - Unique destination hosts
    """

    def __init__(self, time_window_seconds: int = 10):
        if time_window_seconds <= 0:
            raise ValueError(
                "time_window_seconds must be greater than 0."
            )

        self.time_window = timedelta(
            seconds=time_window_seconds
        )

        self.events = defaultdict(list)

    def _get_recent_events(self, source_ip, timestamp):
        """
        Return recent events for a source IP
        within the configured time window.
        """

        cutoff_time = timestamp - self.time_window

        self.events[source_ip] = [
            stored_event
            for stored_event in self.events[source_ip]
            if stored_event.timestamp >= cutoff_time
        ]

        return self.events[source_ip]

    def process_event(self, event) -> dict:
        """
        Register one event and calculate all traffic metrics.
        """

        source_ip = event.source_ip

        self.events[source_ip].append(event)

        recent_events = self._get_recent_events(
            source_ip,
            event.timestamp,
        )

        total_events = len(recent_events)

        # --------------------------------
        # Connection Rate
        # --------------------------------

        connection_rate = (
            total_events
            / self.time_window.total_seconds()
        )

        # --------------------------------
        # Failed Connection Ratio
        # --------------------------------

        failed_connections = 0

        for stored_event in recent_events:
            if stored_event.tcp_flags is not None:
                if "R" in stored_event.tcp_flags:
                    failed_connections += 1

        failed_connection_ratio = (
            failed_connections / total_events
            if total_events > 0
            else 0.0
        )

        # --------------------------------
        # Unique Destination Ports
        # --------------------------------

        unique_ports = {
            stored_event.destination_port
            for stored_event in recent_events
            if stored_event.destination_port is not None
        }

        # --------------------------------
        # Unique Destination Hosts
        # --------------------------------

        unique_hosts = {
            stored_event.destination_ip
            for stored_event in recent_events
            if stored_event.destination_ip != source_ip
        }

        return {
            "connection_rate": connection_rate,
            "failed_connection_ratio": failed_connection_ratio,
            "unique_ports": len(unique_ports),
            "unique_hosts": len(unique_hosts),
        }

    def calculate_connection_rate(self, event) -> float:
        """
        Calculate connection rate for one event.
        """

        source_ip = event.source_ip

        self.events[source_ip].append(event)

        recent_events = self._get_recent_events(
            source_ip,
            event.timestamp,
        )

        return (
            len(recent_events)
            / self.time_window.total_seconds()
        )

    def calculate_failed_connection_ratio(self, event) -> float:
        """
        Calculate failed connection ratio for one event.

        A TCP event is considered failed when its TCP flags
        indicate a reset (RST).
        """

        source_ip = event.source_ip

        self.events[source_ip].append(event)

        recent_events = self._get_recent_events(
            source_ip,
            event.timestamp,
        )

        if not recent_events:
            return 0.0

        failed_connections = 0

        for stored_event in recent_events:
            if stored_event.tcp_flags is not None:
                if "R" in stored_event.tcp_flags:
                    failed_connections += 1

        return failed_connections / len(recent_events)