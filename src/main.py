from src.capture.packet_collector import PacketCollector
from src.config.config_loader import ConfigLoader
from src.detection.behavior_analyzer import BehaviorAnalyzer
from src.detection.detection_pipeline import DetectionPipeline
from src.detection.host_scan_detector import HostScanDetector
from src.detection.port_scan_detector import PortScanDetector
from src.detection.traffic_metrics import TrafficMetrics
from src.logging.event_logger import EventLogger
from src.logging.security_logger import SecurityLogger
from src.scoring.risk_scorer import RiskScorer


CONFIG_PATH = "config/config.yaml"


def handle_event(
    event,
    detection_pipeline,
    traffic_metrics,
    behavior_analyzer,
    scorer,
    security_logger,
    event_logger,
):
    # --------------------------------
    # Log normalized network event
    # --------------------------------

    event_logger.log_event(event)

    print(
        f"[EVENT] "
        f"{event.source_ip} -> {event.destination_ip} | "
        f"{event.protocol} | "
        f"{event.source_port} -> {event.destination_port}"
    )

    # --------------------------------
    # Traffic Metrics
    # --------------------------------

    metrics = traffic_metrics.process_event(event)

    connection_rate = metrics["connection_rate"]
    failed_connection_ratio = metrics["failed_connection_ratio"]
    unique_ports = metrics["unique_ports"]
    unique_hosts = metrics["unique_hosts"]

    # --------------------------------
    # Detection Pipeline
    # --------------------------------

    alerts = detection_pipeline.process_event(
        event,
        metrics={
            "connection_rate": connection_rate,
            "unique_ports": unique_ports,
            "unique_hosts": unique_hosts,
        },
    )

    # --------------------------------
    # Behavioral Analysis
    # --------------------------------

    behavior_alert = behavior_analyzer.process(
        source_ip=event.source_ip,
        connection_rate=connection_rate,
        unique_ports=unique_ports,
        unique_hosts=unique_hosts,
    )

    if behavior_alert is not None:
        alerts.append(behavior_alert)

    # --------------------------------
    # Risk Scoring + Security Logging
    # --------------------------------

    for alert in alerts:

        alert_unique_ports = alert.get(
            "unique_ports",
            unique_ports,
        )

        alert_unique_hosts = alert.get(
            "unique_hosts",
            unique_hosts,
        )

        risk_result = scorer.calculate(
            alert=alert,
            unique_ports=alert_unique_ports,
            unique_hosts=alert_unique_hosts,
            connection_rate=connection_rate,
            failed_connection_ratio=failed_connection_ratio,
        )

        security_alert = {
            **alert,
            "connection_rate": connection_rate,
            "failed_connection_ratio": failed_connection_ratio,
            "unique_ports": alert_unique_ports,
            "unique_hosts": alert_unique_hosts,
            "risk_score": risk_result.score,
            "severity": risk_result.severity,
        }

        security_logger.log_alert(security_alert)

        # --------------------------------
        # Alert Output
        # --------------------------------

        print(
            f"[ALERT] {alert['alert_type']} | "
            f"Source: {alert.get('source_ip')} | "
            f"Unique Ports: {alert_unique_ports} | "
            f"Unique Hosts: {alert_unique_hosts} | "
            f"Connection Rate: {connection_rate:.2f} | "
            f"Failed Ratio: {failed_connection_ratio:.2f} | "
            f"Risk Score: {risk_result.score} | "
            f"Severity: {risk_result.severity}"
        )


def main():
    # --------------------------------
    # Load configuration
    # --------------------------------

    config_loader = ConfigLoader(CONFIG_PATH)
    config = config_loader.load()

    network_config = config["network"]
    detection_config = config["detection"]

    # --------------------------------
    # Port Scan Detector
    # --------------------------------

    port_scan_detector = PortScanDetector(
        time_window_seconds=detection_config["time_window_seconds"],
        unique_ports_threshold=detection_config["unique_ports_threshold"],
    )

    # --------------------------------
    # Host Scan Detector
    # --------------------------------

    host_scan_detector = HostScanDetector(
        time_window_seconds=detection_config["time_window_seconds"],
        unique_hosts_threshold=detection_config["unique_hosts_threshold"],
        alert_cooldown_seconds=30,
    )

    # --------------------------------
    # Behavioral Analyzer
    # --------------------------------

    behavior_analyzer = BehaviorAnalyzer(
        time_window_seconds=detection_config["time_window_seconds"],
        minimum_samples=5,
        deviation_multiplier=3.0,
    )

    # --------------------------------
    # Detection Pipeline
    # --------------------------------

    detection_pipeline = DetectionPipeline(
        detectors=[
            port_scan_detector,
            host_scan_detector,
        ]
    )

    # --------------------------------
    # Traffic Metrics
    # --------------------------------

    traffic_metrics = TrafficMetrics(
        time_window_seconds=detection_config["time_window_seconds"],
    )

    # --------------------------------
    # Risk Scoring
    # --------------------------------

    scorer = RiskScorer()

    # --------------------------------
    # Security Alert Logging
    # --------------------------------

    security_logger = SecurityLogger(
        log_file="logs/security_alerts.jsonl"
    )

    # --------------------------------
    # Network Event Logging
    # --------------------------------

    event_logger = EventLogger(
        log_file="logs/events.jsonl"
    )

    # --------------------------------
    # Packet Collection
    # --------------------------------

    collector = PacketCollector(
        interface=network_config["capture_interface"],
        event_handler=lambda event: handle_event(
            event,
            detection_pipeline,
            traffic_metrics,
            behavior_analyzer,
            scorer,
            security_logger,
            event_logger,
        ),
    )

    collector.start()


if __name__ == "__main__":
    main()