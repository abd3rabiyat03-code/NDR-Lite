from collections import defaultdict
from datetime import timedelta

from src.capture.packet_event import PacketEvent


class PortScanDetector:
    """
    Detects vertical port scanning behavior using
    fixed time windows.

    A vertical scan occurs when one source IP contacts
    many different destination ports on the same destination IP
    within a configured time window.

    The detector evaluates the completed window instead
    of generating an alert as soon as the threshold is reached.
    """

    def __init__(
        self,
        time_window_seconds: int = 10,
        unique_ports_threshold: int = 20,
        alert_cooldown_seconds: int = 30,
    ):
        self.time_window = timedelta(
            seconds=time_window_seconds
        )

        self.unique_ports_threshold = (
            unique_ports_threshold
        )

        self.alert_cooldown = timedelta(
            seconds=alert_cooldown_seconds
        )

        self.events = defaultdict(list)

        self.window_start = {}

        self.last_alert_time = {}

    def process_event(self, event: PacketEvent):
        """
        Process one network event.

        Events are grouped into fixed time windows.
        A completed window is evaluated when the next
        window begins.
        """

        if event.protocol not in {"TCP", "UDP"}:
            return None

        if event.destination_port is None:
            return None

        key = (
            event.source_ip,
            event.destination_ip,
        )

        current_window_start = self.window_start.get(key)

        # First event for this source/destination pair.
        if current_window_start is None:
            self.window_start[key] = event.timestamp
            self.events[key] = [event]
            return None

        current_window_end = (
            current_window_start
            + self.time_window
        )

        # Event still belongs to the current window.
        if event.timestamp < current_window_end:
            self.events[key].append(event)
            return None

        # The current window is complete.
        window_events = self.events[key]

        unique_ports = {
            stored_event.destination_port
            for stored_event in window_events
            if stored_event.destination_port is not None
        }

        alert = None

        if len(unique_ports) >= self.unique_ports_threshold:

            last_alert = self.last_alert_time.get(key)

            if (
                last_alert is None
                or event.timestamp - last_alert
                >= self.alert_cooldown
            ):
                alert = {
                    "alert_type": "PORT_SCAN",
                    "severity": "HIGH",
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "unique_ports": len(unique_ports),
                    "time_window_seconds": (
                        self.time_window.total_seconds()
                    ),
                    "window_start": (
                        current_window_start.isoformat()
                    ),
                    "window_end": (
                        current_window_end.isoformat()
                    ),
                    "timestamp": event.timestamp.isoformat(),
                }

                self.last_alert_time[key] = event.timestamp

        # Start a new fixed window.
        self.window_start[key] = event.timestamp
        self.events[key] = [event]

        return alert