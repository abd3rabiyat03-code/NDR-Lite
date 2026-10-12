import json
from pathlib import Path


class EventLogger:
    """
    Writes normalized network events as JSON Lines.
    """

    def __init__(self, log_file: str = "logs/events.jsonl"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, event) -> None:
        event_data = {
            "timestamp": event.timestamp.isoformat(),
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "protocol": event.protocol,
            "source_port": event.source_port,
            "destination_port": event.destination_port,
            "packet_size": event.packet_size,
            "tcp_flags": event.tcp_flags,
        }

        with self.log_file.open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write(
                json.dumps(event_data)
                + "\n"
            )