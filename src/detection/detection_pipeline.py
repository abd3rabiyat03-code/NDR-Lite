from typing import List


class DetectionPipeline:
    """
    Coordinates multiple network detection engines.

    Detectors may optionally accept calculated traffic metrics.

    The pipeline also forwards the original event timestamp
    to behavioral analyzers so time-window analysis remains
    consistent with the captured event.
    """

    def __init__(self, detectors: list):
        self.detectors = detectors

    def process_event(
        self,
        event,
        metrics: dict | None = None,
    ) -> List[dict]:
        """
        Send one network event through all registered detectors.

        The metrics argument is optional so existing detectors
        remain fully compatible.
        """

        alerts = []

        for detector in self.detectors:

            if hasattr(detector, "process_event"):
                alert = detector.process_event(event)

            elif hasattr(detector, "process"):
                if metrics is None:
                    alert = None
                else:
                    alert = detector.process(
                        source_ip=event.source_ip,
                        connection_rate=metrics.get(
                            "connection_rate",
                            0.0,
                        ),
                        unique_ports=metrics.get(
                            "unique_ports",
                            0,
                        ),
                        unique_hosts=metrics.get(
                            "unique_hosts",
                            0,
                        ),
                        timestamp=event.timestamp,
                    )

            else:
                continue

            if alert is not None:
                alerts.append(alert)

        return alerts