"""Tests for cybersim.core.config_loader module."""

import pytest
from cybersim.core.config_loader import load_config, get_module_config


class TestConfigLoader:
    def test_load_default_config(self):
        config = load_config()
        assert "general" in config
        assert "ddos" in config
        assert "bruteforce" in config
        assert "ransomware" in config

    def test_get_module_config(self):
        config = load_config()
        ddos = get_module_config(config, "ddos")
        assert ddos is not None
        assert isinstance(ddos, dict)

    def test_get_nonexistent_module(self):
        config = load_config()
        result = get_module_config(config, "nonexistent_module")
        assert result == {} or result is None
