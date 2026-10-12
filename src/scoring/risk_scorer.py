from dataclasses import dataclass


@dataclass(frozen=True)
class RiskResult:
    score: int
    severity: str


class RiskScorer:
    """
    Calculates a risk score based on detected behavior
    and traffic characteristics.
    """

    def __init__(
        self,
        port_scan_points: int = 40,
        host_scan_points: int = 30,
        high_port_count_points: int = 20,
        high_host_count_points: int = 20,
        connection_rate_points: int = 20,
        failed_connection_points: int = 20,
    ):
        self.port_scan_points = port_scan_points
        self.host_scan_points = host_scan_points
        self.high_port_count_points = high_port_count_points
        self.high_host_count_points = high_host_count_points
        self.connection_rate_points = connection_rate_points
        self.failed_connection_points = failed_connection_points

    def calculate(
        self,
        alert: dict,
        unique_ports: int = 0,
        unique_hosts: int = 0,
        connection_rate: float = 0.0,
        failed_connection_ratio: float = 0.0,
    ) -> RiskResult:

        score = 0

        alert_type = alert.get("alert_type")

        # --------------------------------
        # Detection Type
        # --------------------------------

        if alert_type == "PORT_SCAN":
            score += self.port_scan_points

        if alert_type == "HOST_SCAN":
            score += self.host_scan_points

        # --------------------------------
        # Port / Host Volume
        # --------------------------------

        if unique_ports >= 50:
            score += self.high_port_count_points

        if unique_hosts >= 20:
            score += self.high_host_count_points

        # --------------------------------
        # Connection Rate
        # --------------------------------

        if connection_rate >= 10:
            score += self.connection_rate_points

        # --------------------------------
        # Failed Connection Ratio
        # --------------------------------

        if failed_connection_ratio >= 0.70:
            score += self.failed_connection_points

        # --------------------------------
        # Maximum Risk
        # --------------------------------

        score = min(score, 100)

        severity = self._get_severity(score)

        return RiskResult(
            score=score,
            severity=severity,
        )

    @staticmethod
    def _get_severity(score: int) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        return "LOW"