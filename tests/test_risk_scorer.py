from src.scoring.risk_scorer import RiskScorer


def test_port_scan_has_medium_risk():
    scorer = RiskScorer()

    alert = {
        "alert_type": "PORT_SCAN",
    }

    result = scorer.calculate(alert)

    assert result.score == 40
    assert result.severity == "MEDIUM"


def test_host_scan_has_medium_risk():
    scorer = RiskScorer()

    alert = {
        "alert_type": "HOST_SCAN",
    }

    result = scorer.calculate(alert)

    assert result.score == 30
    assert result.severity == "MEDIUM"


def test_large_port_scan_has_high_risk():
    scorer = RiskScorer()

    alert = {
        "alert_type": "PORT_SCAN",
    }

    result = scorer.calculate(
        alert,
        unique_ports=50,
    )

    assert result.score == 60
    assert result.severity == "HIGH"


def test_large_host_scan_has_medium_risk():
    scorer = RiskScorer()

    alert = {
        "alert_type": "HOST_SCAN",
    }

    result = scorer.calculate(
        alert,
        unique_hosts=20,
    )

    assert result.score == 50
    assert result.severity == "MEDIUM"


def test_critical_network_behavior():
    scorer = RiskScorer()

    alert = {
        "alert_type": "PORT_SCAN",
    }

    result = scorer.calculate(
        alert,
        unique_ports=50,
        connection_rate=10,
        failed_connection_ratio=0.70,
    )

    assert result.score == 100
    assert result.severity == "CRITICAL"


def test_critical_score_is_capped_at_100():
    scorer = RiskScorer()

    alert = {
        "alert_type": "PORT_SCAN",
    }

    result = scorer.calculate(
        alert,
        unique_ports=100,
        unique_hosts=100,
        connection_rate=100,
        failed_connection_ratio=1.0,
    )

    assert result.score == 100
    assert result.severity == "CRITICAL"


def test_normal_traffic_has_low_risk():
    scorer = RiskScorer()

    alert = {
        "alert_type": "NORMAL_TRAFFIC",
    }

    result = scorer.calculate(alert)

    assert result.score == 0
    assert result.severity == "LOW"