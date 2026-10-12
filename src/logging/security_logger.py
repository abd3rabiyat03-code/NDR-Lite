import json
from pathlib import Path


class SecurityLogger:
    """
    Writes security alerts as structured JSON Lines.

    Each alert is stored as one JSON object per line,
    making the log suitable for SIEM ingestion.
    """

    def __init__(self, log_file: str = "logs/security_alerts.jsonl"):
        self.log_file = Path(log_file)

        # Create the parent directory if it does not exist.
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_alert(self, alert: dict) -> None:
        """
        Write one security alert to the JSONL log.
        """

        with self.log_file.open(
            "a",
            encoding="utf-8",
        ) as file:

            file.write(
                json.dumps(
                    alert,
                    ensure_ascii=False,
                )
                + "\n"
            )