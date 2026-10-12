from src.scoring.risk_scorer import RiskScorer


def test_high_connection_rate_increases_risk_score():
    scorer = RiskScorer()

    alert = {
        "alert_type": "PORT_SCAN",
    }

    result = scorer.calculate(
        alert=alert,
        connection_rate=10.0,
    )

    assert result.score == 60
    assert result.severity == "HIGH"


def test_high_failed_connection_ratio_increases_risk_score():
    scorer = RiskScorer()

    alert = {
        "alert_type": "PORT_SCAN",
    }

    result = scorer.calculate(
        alert=alert,
        failed_connection_ratio=0.70,
    )

    assert result.score == 60
    assert result.severity == "HIGH"


def test_multiple_risk_indicators_are_combined():
    scorer = RiskScorer()

    alert = {
        "alert_type": "PORT_SCAN",
    }

    result = scorer.calculate(
        alert=alert,
        unique_ports=50,
        connection_rate=10.0,
        failed_connection_ratio=0.70,
    )

    assert result.score == 100
    assert result.severity == "CRITICAL"