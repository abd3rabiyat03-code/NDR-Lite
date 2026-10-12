from pathlib import Path

import yaml


class ConfigLoader:
    """
    Loads and validates the NDR configuration from YAML.
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = Path(config_path)

    def load(self) -> dict:
        """
        Load the YAML configuration file.
        """

        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}"
            )

        with self.config_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            config = yaml.safe_load(file)

        if not isinstance(config, dict):
            raise ValueError(
                "Configuration must contain a YAML mapping."
            )

        self._validate(config)

        return config

    @staticmethod
    def _validate(config: dict) -> None:
        """
        Validate required configuration sections and values.
        """

        required_sections = {
            "network",
            "detection",
            "response",
            "logging",
        }

        missing_sections = required_sections - config.keys()

        if missing_sections:
            raise ValueError(
                f"Missing configuration sections: "
                f"{', '.join(sorted(missing_sections))}"
            )

        network = config["network"]
        detection = config["detection"]
        response = config["response"]

        # -----------------------------
        # Network configuration
        # -----------------------------

        if not isinstance(
            network.get("capture_interface"),
            str,
        ):
            raise ValueError(
                "network.capture_interface must be a string."
            )

        # -----------------------------
        # Detection configuration
        # -----------------------------

        if not isinstance(
            detection.get("time_window_seconds"),
            int,
        ):
            raise ValueError(
                "detection.time_window_seconds must be an integer."
            )

        if detection["time_window_seconds"] <= 0:
            raise ValueError(
                "detection.time_window_seconds must be greater than 0."
            )

        if not isinstance(
            detection.get("unique_ports_threshold"),
            int,
        ):
            raise ValueError(
                "detection.unique_ports_threshold must be an integer."
            )

        if detection["unique_ports_threshold"] <= 0:
            raise ValueError(
                "detection.unique_ports_threshold must be greater than 0."
            )

        if not isinstance(
            detection.get("unique_hosts_threshold"),
            int,
        ):
            raise ValueError(
                "detection.unique_hosts_threshold must be an integer."
            )

        if detection["unique_hosts_threshold"] <= 0:
            raise ValueError(
                "detection.unique_hosts_threshold must be greater than 0."
            )

        # -----------------------------
        # Response configuration
        # -----------------------------

        if response.get("mode") not in {
            "detection_only",
            "automated_response",
        }:
            raise ValueError(
                "response.mode must be either "
                "'detection_only' or 'automated_response'."
            )