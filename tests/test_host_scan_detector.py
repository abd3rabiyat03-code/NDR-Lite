from datetime import datetime, timedelta, timezone

from src.capture.packet_event import PacketEvent
from src.detection.host_scan_detector import HostScanDetector


def create_event(
    source_ip: str,
    destination_ip: str,
    timestamp: datetime,
) -> PacketEvent:
    return PacketEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="TCP",
        source_port=50000,
        destination_port=80,
        packet_size=60,
        tcp_flags="S",
    )


def test_host_scan_detected():
    detector = HostScanDetector(
        time_window_seconds=10,
        unique_hosts_threshold=5,
    )

    base_time = datetime.now(timezone.utc)

    alert = None

    for host_number in range(1, 6):
        event = create_event(
            source_ip="192.168.56.102",
            destination_ip=f"192.168.56.{200 + host_number}",
            timestamp=base_time + timedelta(
                milliseconds=100 * host_number
            ),
        )

        alert = detector.process_event(event)

    assert alert is not None
    assert alert["alert_type"] == "HOST_SCAN"
    assert alert["source_ip"] == "192.168.56.102"
    assert alert["unique_hosts"] >= 5


def test_normal_host_traffic_does_not_trigger_scan():
    detector = HostScanDetector(
        time_window_seconds=10,
        unique_hosts_threshold=5,
    )

    base_time = datetime.now(timezone.utc)

    alert = None

    for host_number in range(1, 4):
        event = create_event(
            source_ip="192.168.56.102",
            destination_ip=f"192.168.56.{200 + host_number}",
            timestamp=base_time,
        )

        alert = detector.process_event(event)

    assert alert is None


def test_hosts_outside_time_window_do_not_trigger_scan():
    detector = HostScanDetector(
        time_window_seconds=10,
        unique_hosts_threshold=5,
    )

    base_time = datetime.now(timezone.utc)

    alert = None

    # First two hosts.
    for host_number in range(1, 3):
        event = create_event(
            source_ip="192.168.56.102",
            destination_ip=f"192.168.56.{200 + host_number}",
            timestamp=base_time,
        )

        alert = detector.process_event(event)

    # Three additional hosts arrive 20 seconds later.
    # The first two hosts should be outside the 10-second window.
    for host_number in range(3, 6):
        event = create_event(
            source_ip="192.168.56.102",
            destination_ip=f"192.168.56.{200 + host_number}",
            timestamp=base_time + timedelta(seconds=20),
        )

        alert = detector.process_event(event)

    assert alert is None


def test_host_scan_alert_cooldown():
    detector = HostScanDetector(
        time_window_seconds=10,
        unique_hosts_threshold=5,
        alert_cooldown_seconds=30,
    )

    base_time = datetime.now(timezone.utc)

    first_alert = None

    # Generate the first HOST_SCAN alert.
    for host_number in range(1, 6):
        event = create_event(
            source_ip="192.168.56.102",
            destination_ip=f"192.168.56.{200 + host_number}",
            timestamp=base_time + timedelta(
                milliseconds=100 * host_number
            ),
        )

        result = detector.process_event(event)

        if result is not None:
            first_alert = result

    assert first_alert is not None
    assert first_alert["alert_type"] == "HOST_SCAN"
    assert first_alert["source_ip"] == "192.168.56.102"
    assert first_alert["unique_hosts"] >= 5

    # Another event arrives during the 30-second cooldown.
    next_event = create_event(
        source_ip="192.168.56.102",
        destination_ip="192.168.56.210",
        timestamp=base_time + timedelta(seconds=6),
    )

    second_alert = detector.process_event(next_event)

    assert second_alert is None


def test_host_scan_simulated_attack():
    detector = HostScanDetector(
        time_window_seconds=10,
        unique_hosts_threshold=5,
        alert_cooldown_seconds=30,
    )

    base_time = datetime.now(timezone.utc)

    alerts = []

    # Simulate one source contacting multiple hosts.
    for host_number in range(1, 11):
        event = create_event(
            source_ip="192.168.56.102",
            destination_ip=f"192.168.56.{100 + host_number}",
            timestamp=base_time + timedelta(
                milliseconds=100 * host_number
            ),
        )

        alert = detector.process_event(event)

        if alert is not None:
            alerts.append(alert)

    # A HOST_SCAN alert must have been generated.
    assert len(alerts) >= 1

    first_alert = alerts[0]

    assert first_alert["alert_type"] == "HOST_SCAN"
    assert first_alert["source_ip"] == "192.168.56.102"
    assert first_alert["unique_hosts"] >= 5

    # Cooldown should prevent repeated alerts.
    assert len(alerts) == 1