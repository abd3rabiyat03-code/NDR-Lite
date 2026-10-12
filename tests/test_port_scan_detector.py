from datetime import datetime, timedelta, timezone

from src.capture.packet_event import PacketEvent
from src.detection.port_scan_detector import PortScanDetector


def create_tcp_event(
    source_ip,
    destination_ip,
    destination_port,
    timestamp,
):
    return PacketEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="TCP",
        source_port=50000,
        destination_port=destination_port,
        packet_size=60,
        tcp_flags="S",
    )


def test_port_scan_detected():
    detector = PortScanDetector(
        time_window_seconds=10,
        unique_ports_threshold=20,
    )

    base_time = datetime.now(timezone.utc)

    # Generate the scan traffic during the first window.
    for port in range(1, 21):
        event = create_tcp_event(
            source_ip="192.168.56.102",
            destination_ip="192.168.56.101",
            destination_port=port,
            timestamp=base_time
            + timedelta(milliseconds=100 * port),
        )

        result = detector.process_event(event)

        # The detector waits until the window is complete.
        assert result is None

    # Move slightly beyond the 10-second window.
    final_event = create_tcp_event(
        source_ip="192.168.56.102",
        destination_ip="192.168.56.101",
        destination_port=80,
        timestamp=base_time
        + timedelta(
            seconds=10,
            milliseconds=100,
        ),
    )

    alert = detector.process_event(final_event)

    assert alert is not None
    assert alert["alert_type"] == "PORT_SCAN"
    assert alert["source_ip"] == "192.168.56.102"
    assert alert["destination_ip"] == "192.168.56.101"
    assert alert["unique_ports"] >= 20


def test_normal_traffic_does_not_trigger_port_scan():
    detector = PortScanDetector(
        time_window_seconds=10,
        unique_ports_threshold=20,
    )

    base_time = datetime.now(timezone.utc)

    for port in range(1, 10):
        event = create_tcp_event(
            source_ip="192.168.56.102",
            destination_ip="192.168.56.101",
            destination_port=port,
            timestamp=base_time
            + timedelta(seconds=port),
        )

        result = detector.process_event(event)

        assert result is None


def test_port_scan_alert_cooldown():
    detector = PortScanDetector(
        time_window_seconds=10,
        unique_ports_threshold=3,
        alert_cooldown_seconds=30,
    )

    base_time = datetime.now(timezone.utc)

    # First scan window.
    for i, port in enumerate([21, 22, 23]):
        event = create_tcp_event(
            source_ip="192.168.56.102",
            destination_ip="192.168.56.101",
            destination_port=port,
            timestamp=base_time
            + timedelta(seconds=i),
        )

        result = detector.process_event(event)

        if i < 2:
            assert result is None

    # Complete the first window.
    first_alert = detector.process_event(
        create_tcp_event(
            source_ip="192.168.56.102",
            destination_ip="192.168.56.101",
            destination_port=24,
            timestamp=base_time
            + timedelta(
                seconds=10,
                milliseconds=100,
            ),
        )
    )

    assert first_alert is not None
    assert first_alert["alert_type"] == "PORT_SCAN"

    # Second scan occurs within cooldown period.
    second_alert = detector.process_event(
        create_tcp_event(
            source_ip="192.168.56.102",
            destination_ip="192.168.56.101",
            destination_port=25,
            timestamp=base_time + timedelta(seconds=20),
        )
    )

    assert second_alert is None