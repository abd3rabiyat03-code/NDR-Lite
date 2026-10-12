from datetime import datetime, timezone
from typing import Callable, Optional

from scapy.all import IP, TCP, UDP, ICMP, sniff

from .packet_event import PacketEvent


class PacketCollector:
    """
    Captures network packets and converts them into normalized
    PacketEvent objects.

    This collector intentionally stores network metadata only.
    Packet payloads are not retained.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        event_handler: Optional[Callable[[PacketEvent], None]] = None,
    ):
        self.interface = interface
        self.event_handler = event_handler

    def _packet_to_event(self, packet) -> Optional[PacketEvent]:
        """Convert a Scapy packet into a normalized PacketEvent."""

        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]

        protocol = "OTHER"
        source_port = None
        destination_port = None
        tcp_flags = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        return PacketEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip=ip_layer.src,
            destination_ip=ip_layer.dst,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            packet_size=len(packet),
            tcp_flags=tcp_flags,
        )

    def _process_packet(self, packet) -> None:
        """Process one captured packet."""

        try:
            event = self._packet_to_event(packet)

            if event is None:
                return

            if self.event_handler:
                self.event_handler(event)

        except Exception as exc:
            print(f"[COLLECTOR ERROR] {exc}")

    def start(self) -> None:
        """Start packet capture."""

        print("[NDR] Packet collector started.")
        print("[NDR] Press Ctrl+C to stop.")

        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
        )