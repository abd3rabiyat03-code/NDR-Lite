import pytest

from src.config.config_loader import ConfigLoader


def test_config_loader_loads_configuration():
    loader = ConfigLoader("config/config.yaml")

    config = loader.load()

    assert (
        config["network"]["capture_interface"]
        == r"\Device\NPF_{C22D98E7-57AF-43C0-9DBC-D2888D6078EB}"
    )
    assert config["detection"]["time_window_seconds"] == 10
    assert config["detection"]["unique_ports_threshold"] == 20
    assert config["response"]["mode"] == "detection_only"
    assert config["logging"]["level"] == "INFO"


def test_invalid_time_window_is_rejected(tmp_path):
    config_file = tmp_path / "config.yaml"

    config_file.write_text(
        """
network:
  capture_interface: "Ethernet 2"

detection:
  time_window_seconds: 0
  unique_ports_threshold: 20

response:
  mode: "detection_only"

logging:
  level: "INFO"
""",
        encoding="utf-8",
    )

    loader = ConfigLoader(str(config_file))

    with pytest.raises(ValueError):
        loader.load()


def test_invalid_port_threshold_is_rejected(tmp_path):
    config_file = tmp_path / "config.yaml"

    config_file.write_text(
        """
network:
  capture_interface: "Ethernet 2"

detection:
  time_window_seconds: 10
  unique_ports_threshold: -5

response:
  mode: "detection_only"

logging:
  level: "INFO"
""",
        encoding="utf-8",
    )

    loader = ConfigLoader(str(config_file))

    with pytest.raises(ValueError):
        loader.load()


def test_invalid_response_mode_is_rejected(tmp_path):
    config_file = tmp_path / "config.yaml"

    config_file.write_text(
        """
network:
  capture_interface: "Ethernet 2"

detection:
  time_window_seconds: 10
  unique_ports_threshold: 20

response:
  mode: "unknown_mode"

logging:
  level: "INFO"
""",
        encoding="utf-8",
    )

    loader = ConfigLoader(str(config_file))

    with pytest.raises(ValueError):
        loader.load()