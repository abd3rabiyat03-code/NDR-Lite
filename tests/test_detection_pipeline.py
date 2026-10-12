from datetime import datetime, timedelta, timezone

from src.capture.packet_event import PacketEvent
from src.detection.detection_pipeline import DetectionPipeline
from src.detection.port_scan_detector import PortScanDetector
from src.detection.behavior_analyzer import BehaviorAnalyzer
from src.scoring.risk_scorer import RiskScorer


def test_detection_to_risk_pipeline():
    detector = PortScanDetector(
        time_window_seconds=10,
        unique_ports_threshold=20,
    )

    scorer = RiskScorer()

    timestamp = datetime.now(timezone.utc)

    # Generate scan traffic inside the detection window.
    for port in range(1, 21):
        event = PacketEvent(
            timestamp=timestamp,
            source_ip="192.168.56.102",
            destination_ip="192.168.56.101",
            protocol="TCP",
            source_port=50000,
            destination_port=port,
            packet_size=60,
            tcp_flags="S",
        )

        result = detector.process_event(event)

        # The detector should wait for the complete window.
        assert result is None

    # Move to the end of the time window.
    final_event = PacketEvent(
        timestamp=timestamp + timedelta(seconds=10),
        source_ip="192.168.56.102",
        destination_ip="192.168.56.101",
        protocol="TCP",
        source_port=50000,
        destination_port=80,
        packet_size=60,
        tcp_flags="S",
    )

    alert = detector.process_event(final_event)

    assert alert is not None
    assert alert["alert_type"] == "PORT_SCAN"
    assert alert["unique_ports"] >= 20

    risk_result = scorer.calculate(
        alert=alert,
        unique_ports=alert["unique_ports"],
    )

    assert risk_result.score == 40
    assert risk_result.severity == "MEDIUM"


class FakeDetector:
    def __init__(self, alert=None):
        self.alert = alert
        self.received_events = []

    def process_event(self, event):
        self.received_events.append(event)
        return self.alert


def create_test_event():
    return PacketEvent(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.56.102",
        destination_ip="192.168.56.1",
        protocol="TCP",
        source_port=50000,
        destination_port=80,
        packet_size=60,
        tcp_flags="S",
    )


def test_detection_pipeline_sends_event_to_all_detectors():
    detector_one = FakeDetector()
    detector_two = FakeDetector()

    pipeline = DetectionPipeline(
        detectors=[
            detector_one,
            detector_two,
        ]
    )

    event = create_test_event()

    alerts = pipeline.process_event(event)

    assert alerts == []

    assert detector_one.received_events == [event]
    assert detector_two.received_events == [event]


def test_detection_pipeline_returns_generated_alerts():
    alert_one = {
        "alert_type": "PORT_SCAN",
        "source_ip": "192.168.56.102",
    }

    alert_two = {
        "alert_type": "HOST_SCAN",
        "source_ip": "192.168.56.102",
    }

    detector_one = FakeDetector(alert_one)
    detector_two = FakeDetector(alert_two)

    pipeline = DetectionPipeline(
        detectors=[
            detector_one,
            detector_two,
        ]
    )

    event = create_test_event()

    alerts = pipeline.process_event(event)

    assert alerts == [
        alert_one,
        alert_two,
    ]


def test_detection_pipeline_returns_only_generated_alerts():
    alert = {
        "alert_type": "PORT_SCAN",
        "source_ip": "192.168.56.102",
    }

    detector_one = FakeDetector(alert)
    detector_two = FakeDetector()

    pipeline = DetectionPipeline(
        detectors=[
            detector_one,
            detector_two,
        ]
    )

    event = create_test_event()

    alerts = pipeline.process_event(event)

    assert alerts == [alert]


def test_detection_pipeline_supports_behavior_analyzer():
    analyzer = BehaviorAnalyzer(
        time_window_seconds=10,
        minimum_samples=3,
        deviation_multiplier=3.0,
    )

    pipeline = DetectionPipeline(
        detectors=[
            analyzer,
        ]
    )

    source_ip = "192.168.56.102"

    normal_metrics = {
        "connection_rate": 1.0,
        "unique_ports": 2,
        "unique_hosts": 1,
    }

    # Create three completed normal windows.
    normal_times = [
        datetime(
            2026,
            10,
            4,
            8,
            0,
            0,
            tzinfo=timezone.utc,
        ),
        datetime(
            2026,
            10,
            4,
            8,
            0,
            10,
            tzinfo=timezone.utc,
        ),
        datetime(
            2026,
            10,
            4,
            8,
            0,
            20,
            tzinfo=timezone.utc,
        ),
        datetime(
            2026,
            10,
            4,
            8,
            0,
            30,
            tzinfo=timezone.utc,
        ),
    ]

    for timestamp in normal_times:
        event = PacketEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip="192.168.56.1",
            protocol="TCP",
            source_port=50000,
            destination_port=80,
            packet_size=60,
            tcp_flags="S",
        )

        alerts = pipeline.process_event(
            event,
            metrics=normal_metrics,
        )

        assert alerts == []

    # Create the anomalous window.
    anomaly_event = PacketEvent(
        timestamp=datetime(
            2026,
            10,
            4,
            8,
            0,
            40,
            tzinfo=timezone.utc,
        ),
        source_ip=source_ip,
        destination_ip="192.168.56.1",
        protocol="TCP",
        source_port=50000,
        destination_port=80,
        packet_size=60,
        tcp_flags="S",
    )

    anomaly_metrics = {
        "connection_rate": 5.0,
        "unique_ports": 10,
        "unique_hosts": 5,
    }

    alerts = pipeline.process_event(
        anomaly_event,
        metrics=anomaly_metrics,
    )

    assert alerts == []

    # Move to the next window.
    # This causes the anomalous window to be analyzed.
    next_event = PacketEvent(
        timestamp=datetime(
            2026,
            10,
            4,
            8,
            0,
            50,
            tzinfo=timezone.utc,
        ),
        source_ip=source_ip,
        destination_ip="192.168.56.1",
        protocol="TCP",
        source_port=50000,
        destination_port=80,
        packet_size=60,
        tcp_flags="S",
    )

    alerts = pipeline.process_event(
        next_event,
        metrics=normal_metrics,
    )

    assert len(alerts) == 1

    assert alerts[0]["alert_type"] == "BEHAVIOR_ANOMALY"

    assert "CONNECTION_RATE_ANOMALY" in alerts[0]["anomalies"]

    assert "PORT_BEHAVIOR_ANOMALY" in alerts[0]["anomalies"]

    assert "HOST_BEHAVIOR_ANOMALY" in alerts[0]["anomalies"]