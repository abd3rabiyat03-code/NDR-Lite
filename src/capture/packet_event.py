from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class PacketEvent:
    """
    Normalized network event produced by the packet collector.

    Only network metadata required for detection is stored.
    Packet payloads are intentionally excluded.
    """

    timestamp: datetime

    source_ip: str
    destination_ip: str

    protocol: str

    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    packet_size: int = 0

    tcp_flags: Optional[str] = None