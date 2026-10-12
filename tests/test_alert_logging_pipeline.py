from datetime import datetime, timedelta, timezone

from src.capture.packet_event import PacketEvent
from src.detection.port_scan_detector import PortScanDetector
from src.logging.security_logger import SecurityLogger
from src.scoring.risk_scorer import RiskScorer


def test_alert_logging_pipeline(tmp_path):
    detector = PortScanDetector(
        time_window_seconds=10,
        unique_ports_threshold=20,
    )

    scorer = RiskScorer()

    log_file = tmp_path / "security_alerts.jsonl"

    logger = SecurityLogger(
        log_file=str(log_file)
    )

    timestamp = datetime.now(timezone.utc)

    # Generate 20 synthetic TCP events
    # inside the same detection window.
    # No real network scanning is performed.
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

        # The detector evaluates the completed window,
        # so no alert is expected yet.
        assert result is None

    # Send an event after the 10-second window to close
    # the previous window and trigger the alert.
    final_event = PacketEvent(
        timestamp=timestamp + timedelta(
            seconds=10,
            milliseconds=100,
        ),
        source_ip="192.168.56.102",
        destination_ip="192.168.56.101",
        protocol="TCP",
        source_port=50000,
        destination_port=9999,
        packet_size=60,
        tcp_flags="S",
    )

    alert = detector.process_event(final_event)

    assert alert is not None
    assert alert["alert_type"] == "PORT_SCAN"
    assert alert["source_ip"] == "192.168.56.102"
    assert alert["destination_ip"] == "192.168.56.101"
    assert alert["unique_ports"] == 20

    risk_result = scorer.calculate(
        alert=alert,
        unique_ports=alert["unique_ports"],
    )

    security_alert = {
        **alert,
        "risk_score": risk_result.score,
        "severity": risk_result.severity,
    }

    logger.log_alert(security_alert)

    assert log_file.exists()

    content = log_file.read_text(
        encoding="utf-8"
    )

    assert "PORT_SCAN" in content
    assert "192.168.56.102" in content
    assert "risk_score" in content