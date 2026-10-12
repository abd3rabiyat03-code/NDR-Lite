from collections import defaultdict
from datetime import timedelta

from src.capture.packet_event import PacketEvent


class HostScanDetector:
    """
    Detects potential horizontal host scanning behavior.

    A horizontal scan occurs when one source IP contacts
    many different destination IP addresses within a short
    time window.

    Duplicate alerts are suppressed using a cooldown period.
    """

    def __init__(
        self,
        time_window_seconds: int = 10,
        unique_hosts_threshold: int = 5,
        alert_cooldown_seconds: int = 30,
    ):
        self.time_window = timedelta(seconds=time_window_seconds)
        self.unique_hosts_threshold = unique_hosts_threshold
        self.alert_cooldown = timedelta(
            seconds=alert_cooldown_seconds
        )

        self.events = defaultdict(list)
        self.last_alert_time = {}

    def process_event(self, event: PacketEvent):
        """
        Process one network event and return an alert
        when horizontal scanning behavior is detected.
        """

        if event.protocol not in {"TCP", "UDP", "ICMP"}:
            return None

        key = event.source_ip

        self.events[key].append(event)

        cutoff_time = event.timestamp - self.time_window

        self.events[key] = [
            stored_event
            for stored_event in self.events[key]
            if stored_event.timestamp >= cutoff_time
        ]

        unique_hosts = {
            stored_event.destination_ip
            for stored_event in self.events[key]
            if stored_event.destination_ip != event.source_ip
        }

        if len(unique_hosts) < self.unique_hosts_threshold:
            return None

        last_alert = self.last_alert_time.get(key)

        if last_alert is not None:
            if event.timestamp - last_alert < self.alert_cooldown:
                return None

        self.last_alert_time[key] = event.timestamp

        return {
            "alert_type": "HOST_SCAN",
            "severity": "MEDIUM",
            "source_ip": event.source_ip,
            "destination_ip": None,
            "unique_hosts": len(unique_hosts),
            "time_window_seconds": self.time_window.total_seconds(),
            "timestamp": event.timestamp.isoformat(),
        }