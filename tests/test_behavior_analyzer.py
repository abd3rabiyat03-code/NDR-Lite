from datetime import datetime, timedelta, timezone

from src.detection.behavior_analyzer import BehaviorAnalyzer


def create_timestamp(seconds: int):
    return datetime(
        2026,
        10,
        4,
        8,
        0,
        seconds,
        tzinfo=timezone.utc,
    )


def test_no_alert_before_minimum_samples():
    analyzer = BehaviorAnalyzer(
        time_window_seconds=10,
        minimum_samples=5,
    )

    for i in range(5):
        analyzer.process(
            source_ip="192.168.56.102",
            connection_rate=1.0,
            unique_ports=2,
            unique_hosts=1,
            timestamp=create_timestamp(i * 10),
        )

    assert len(
        analyzer.history["192.168.56.102"]
    ) == 4


def test_normal_behavior_does_not_trigger_alert():
    analyzer = BehaviorAnalyzer(
        time_window_seconds=10,
        minimum_samples=3,
    )

    for i in range(4):
        analyzer.process(
            source_ip="192.168.56.102",
            connection_rate=1.0,
            unique_ports=2,
            unique_hosts=1,
            timestamp=create_timestamp(i * 10),
        )

    # Start next window.
    result = analyzer.process(
        source_ip="192.168.56.102",
        connection_rate=2.0,
        unique_ports=3,
        unique_hosts=2,
        timestamp=create_timestamp(40),
    )

    assert result is None


def test_connection_rate_anomaly_is_detected():
    analyzer = BehaviorAnalyzer(
        time_window_seconds=10,
        minimum_samples=3,
        deviation_multiplier=3.0,
    )

    # Build normal baseline.
    for i in range(4):
        analyzer.process(
            source_ip="192.168.56.102",
            connection_rate=1.0,
            unique_ports=2,
            unique_hosts=1,
            timestamp=create_timestamp(i * 10),
        )

    # Start anomalous window.
    analyzer.process(
        source_ip="192.168.56.102",
        connection_rate=5.0,
        unique_ports=2,
        unique_hosts=1,
        timestamp=create_timestamp(40),
    )

    # Move to next window.
    # Now the previous anomalous window is analyzed.
    result = analyzer.process(
        source_ip="192.168.56.102",
        connection_rate=1.0,
        unique_ports=2,
        unique_hosts=1,
        timestamp=create_timestamp(50),
    )

    assert result is not None
    assert result["alert_type"] == "BEHAVIOR_ANOMALY"
    assert "CONNECTION_RATE_ANOMALY" in result["anomalies"]


def test_port_behavior_anomaly_is_detected():
    analyzer = BehaviorAnalyzer(
        time_window_seconds=10,
        minimum_samples=3,
        deviation_multiplier=3.0,
    )

    # Build normal baseline.
    for i in range(4):
        analyzer.process(
            source_ip="192.168.56.102",
            connection_rate=1.0,
            unique_ports=2,
            unique_hosts=1,
            timestamp=create_timestamp(i * 10),
        )

    # Start anomalous window.
    analyzer.process(
        source_ip="192.168.56.102",
        connection_rate=1.0,
        unique_ports=10,
        unique_hosts=1,
        timestamp=create_timestamp(40),
    )

    # Move to next window.
    result = analyzer.process(
        source_ip="192.168.56.102",
        connection_rate=1.0,
        unique_ports=2,
        unique_hosts=1,
        timestamp=create_timestamp(50),
    )

    assert result is not None
    assert "PORT_BEHAVIOR_ANOMALY" in result["anomalies"]


def test_host_behavior_anomaly_is_detected():
    analyzer = BehaviorAnalyzer(
        time_window_seconds=10,
        minimum_samples=3,
        deviation_multiplier=3.0,
    )

    # Build normal baseline.
    for i in range(4):
        analyzer.process(
            source_ip="192.168.56.102",
            connection_rate=1.0,
            unique_ports=2,
            unique_hosts=1,
            timestamp=create_timestamp(i * 10),
        )

    # Start anomalous window.
    analyzer.process(
        source_ip="192.168.56.102",
        connection_rate=1.0,
        unique_ports=2,
        unique_hosts=5,
        timestamp=create_timestamp(40),
    )

    # Move to next window.
    result = analyzer.process(
        source_ip="192.168.56.102",
        connection_rate=1.0,
        unique_ports=2,
        unique_hosts=1,
        timestamp=create_timestamp(50),
    )

    assert result is not None
    assert "HOST_BEHAVIOR_ANOMALY" in result["anomalies"]