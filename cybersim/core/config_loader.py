"""
CyberSim6 - Configuration Loader
Loads YAML configuration with defaults.
"""

from pathlib import Path
import yaml


DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "default.yaml"


def load_config(config_path: Path = None) -> dict:
    """Load configuration from YAML file."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_module_config(config: dict, module_name: str) -> dict:
    """Extract a module's config section."""
    return config.get(module_name, {})
