import json

from src.logging.security_logger import SecurityLogger


def test_security_logger_writes_json_alert(tmp_path):
    log_file = tmp_path / "security_alerts.jsonl"

    logger = SecurityLogger(
        log_file=str(log_file)
    )

    alert = {
        "timestamp": "2026-09-28T09:00:00+00:00",
        "alert_type": "PORT_SCAN",
        "source_ip": "192.168.56.102",
        "destination_ip": "192.168.56.101",
        "unique_ports": 20,
        "risk_score": 40,
        "severity": "MEDIUM",
    }

    logger.log_alert(alert)

    assert log_file.exists()

    with log_file.open("r", encoding="utf-8") as file:
        saved_alert = json.loads(file.readline())

    assert saved_alert["alert_type"] == "PORT_SCAN"
    assert saved_alert["source_ip"] == "192.168.56.102"
    assert saved_alert["risk_score"] == 40
    assert saved_alert["severity"] == "MEDIUM"