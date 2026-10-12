from src.detection.behavior_analyzer import BehaviorAnalyzer


class BehaviorDetector:
    """
    Adapter that allows BehaviorAnalyzer to operate
    inside the DetectionPipeline.
    """

    def __init__(self, analyzer: BehaviorAnalyzer):
        self.analyzer = analyzer

    def process_event(self, event):
        """
        Convert the current PacketEvent into behavioral
        metrics and pass them to the analyzer.

        The adapter expects metrics to be attached to the event
        by the application layer.
        """

        metrics = getattr(event, "behavior_metrics", None)

        if metrics is None:
            return None

        return self.analyzer.process(
            source_ip=event.source_ip,
            connection_rate=metrics["connection_rate"],
            unique_ports=metrics["unique_ports"],
            unique_hosts=metrics["unique_hosts"],
        )