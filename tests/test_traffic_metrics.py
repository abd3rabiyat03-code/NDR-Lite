from datetime import datetime, timedelta, timezone

import pytest

from src.capture.packet_event import PacketEvent
from src.detection.traffic_metrics import TrafficMetrics


def create_event(
    source_ip: str,
    timestamp: datetime,
) -> PacketEvent:
    return PacketEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip="192.168.56.1",
        protocol="TCP",
        source_port=50000,
        destination_port=80,
        packet_size=60,
        tcp_flags="S",
    )


def test_connection_rate():
    metrics = TrafficMetrics(
        time_window_seconds=10,
    )

    base_time = datetime.now(timezone.utc)

    rate = 0.0

    for i in range(100):
        event = create_event(
            source_ip="192.168.56.102",
            timestamp=base_time + timedelta(
                milliseconds=i * 10
            ),
        )

        rate = metrics.calculate_connection_rate(event)

    assert rate == pytest.approx(10.0)


def test_connection_rate_uses_time_window():
    metrics = TrafficMetrics(
        time_window_seconds=10,
    )

    base_time = datetime.now(timezone.utc)

    # Five events inside the window.
    for i in range(5):
        event = create_event(
            source_ip="192.168.56.102",
            timestamp=base_time + timedelta(
                seconds=i
            ),
        )

        metrics.calculate_connection_rate(event)

    # Move 20 seconds forward.
    # Previous events should now be outside the window.
    event = create_event(
        source_ip="192.168.56.102",
        timestamp=base_time + timedelta(seconds=20),
    )

    rate = metrics.calculate_connection_rate(event)

    assert rate == pytest.approx(0.1)


def test_different_sources_are_tracked_separately():
    metrics = TrafficMetrics(
        time_window_seconds=10,
    )

    base_time = datetime.now(timezone.utc)

    for i in range(10):
        metrics.calculate_connection_rate(
            create_event(
                source_ip="192.168.56.102",
                timestamp=base_time + timedelta(
                    milliseconds=i * 10
                ),
            )
        )

    rate = metrics.calculate_connection_rate(
        create_event(
            source_ip="192.168.56.103",
            timestamp=base_time,
        )
    )

    assert rate == pytest.approx(0.1)


def test_invalid_time_window_is_rejected():
    with pytest.raises(ValueError):
        TrafficMetrics(time_window_seconds=0)

    with pytest.raises(ValueError):
        TrafficMetrics(time_window_seconds=-1)


def test_failed_connection_ratio():
    metrics = TrafficMetrics(
        time_window_seconds=10,
    )

    base_time = datetime.now(timezone.utc)

    failed_events = 7
    successful_events = 3

    for i in range(failed_events):
        event = PacketEvent(
            timestamp=base_time + timedelta(
                milliseconds=i * 10
            ),
            source_ip="192.168.56.102",
            destination_ip="192.168.56.1",
            protocol="TCP",
            source_port=50000 + i,
            destination_port=80,
            packet_size=60,
            tcp_flags="R",
        )

        ratio = metrics.calculate_failed_connection_ratio(event)

    for i in range(successful_events):
        event = PacketEvent(
            timestamp=base_time + timedelta(
                milliseconds=(failed_events + i) * 10
            ),
            source_ip="192.168.56.102",
            destination_ip="192.168.56.1",
            protocol="TCP",
            source_port=51000 + i,
            destination_port=80,
            packet_size=60,
            tcp_flags="SA",
        )

        ratio = metrics.calculate_failed_connection_ratio(event)

    assert ratio == pytest.approx(0.70)


def test_failed_connection_ratio_no_failures():
    metrics = TrafficMetrics(
        time_window_seconds=10,
    )

    base_time = datetime.now(timezone.utc)

    for i in range(10):
        event = PacketEvent(
            timestamp=base_time + timedelta(
                milliseconds=i * 10
            ),
            source_ip="192.168.56.102",
            destination_ip="192.168.56.1",
            protocol="TCP",
            source_port=50000 + i,
            destination_port=80,
            packet_size=60,
            tcp_flags="SA",
        )

        ratio = metrics.calculate_failed_connection_ratio(event)

    assert ratio == pytest.approx(0.0)


def test_failed_connection_ratio_uses_time_window():
    metrics = TrafficMetrics(
        time_window_seconds=10,
    )

    base_time = datetime.now(timezone.utc)

    # Old failed connections.
    for i in range(5):
        event = PacketEvent(
            timestamp=base_time,
            source_ip="192.168.56.102",
            destination_ip="192.168.56.1",
            protocol="TCP",
            source_port=50000 + i,
            destination_port=80,
            packet_size=60,
            tcp_flags="R",
        )

        metrics.calculate_failed_connection_ratio(event)

    # After 20 seconds, old events are outside the window.
    event = PacketEvent(
        timestamp=base_time + timedelta(seconds=20),
        source_ip="192.168.56.102",
        destination_ip="192.168.56.1",
        protocol="TCP",
        source_port=51000,
        destination_port=80,
        packet_size=60,
        tcp_flags="SA",
    )

    ratio = metrics.calculate_failed_connection_ratio(event)

    assert ratio == pytest.approx(0.0)


def test_process_event_calculates_unique_ports():
    metrics = TrafficMetrics(
        time_window_seconds=10,
    )

    base_time = datetime.now(timezone.utc)

    result = None

    for port in [80, 443, 22, 8080]:
        event = PacketEvent(
            timestamp=base_time,
            source_ip="192.168.56.102",
            destination_ip="192.168.56.1",
            protocol="TCP",
            source_port=50000,
            destination_port=port,
            packet_size=60,
            tcp_flags="S",
        )

        result = metrics.process_event(event)

    assert result["unique_ports"] == 4


def test_process_event_calculates_unique_hosts():
    metrics = TrafficMetrics(
        time_window_seconds=10,
    )

    base_time = datetime.now(timezone.utc)

    destinations = [
        "192.168.56.1",
        "192.168.56.2",
        "192.168.56.3",
        "192.168.56.4",
    ]

    result = None

    for destination in destinations:
        event = PacketEvent(
            timestamp=base_time,
            source_ip="192.168.56.102",
            destination_ip=destination,
            protocol="TCP",
            source_port=50000,
            destination_port=80,
            packet_size=60,
            tcp_flags="S",
        )

        result = metrics.process_event(event)

    assert result["unique_hosts"] == 4