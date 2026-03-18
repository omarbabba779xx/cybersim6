"""Tests for cybersim.core.base_module — BaseModule abstract class."""
import pytest
from cybersim.core.base_module import BaseModule
from cybersim.core.logging_engine import CyberSimLogger


class ConcreteModule(BaseModule):
    MODULE_TYPE = "attack"
    MODULE_NAME = "test_module"

    def _validate_safety(self):
        pass  # No safety constraints for tests

    def run(self, **kwargs):
        self._running = True
        self.log_event("run_started", {"message": "running", "status": "info"})
        self._running = False

    def stop(self):
        self._running = False


class FailingSafetyModule(BaseModule):
    MODULE_TYPE = "attack"
    MODULE_NAME = "unsafe_module"

    def _validate_safety(self):
        raise ValueError("Safety check failed")

    def run(self, **kwargs):
        pass

    def stop(self):
        pass


@pytest.fixture
def logger():
    return CyberSimLogger()


@pytest.fixture
def config():
    return {"target": "127.0.0.1", "port": 8080}


class TestBaseModule:
    def test_instantiation(self, config, logger):
        m = ConcreteModule(config, logger)
        assert m.config == config
        assert m.logger is logger
        assert m._running is False

    def test_log_event_emits_to_logger(self, config, logger):
        m = ConcreteModule(config, logger)
        m.log_event("test_event", {"message": "hello", "status": "info"})
        assert len(logger.events) == 1
        ev = logger.events[0]
        assert ev["module"] == "test_module"
        assert ev["module_type"] == "attack"
        assert ev["event_type"] == "test_event"

    def test_log_event_empty_details(self, config, logger):
        m = ConcreteModule(config, logger)
        m.log_event("bare_event")
        assert len(logger.events) == 1

    def test_run_sets_running_state(self, config, logger):
        m = ConcreteModule(config, logger)
        m.run()
        assert m._running is False  # reset after run completes

    def test_stop_clears_running(self, config, logger):
        m = ConcreteModule(config, logger)
        m._running = True
        m.stop()
        assert m._running is False

    def test_cannot_instantiate_abstract(self, config, logger):
        with pytest.raises(TypeError):
            BaseModule(config, logger)

    def test_safety_check_runs_on_init(self, config, logger):
        with pytest.raises(ValueError, match="Safety check failed"):
            FailingSafetyModule(config, logger)

    def test_multiple_events_accumulate(self, config, logger):
        m = ConcreteModule(config, logger)
        for i in range(5):
            m.log_event(f"event_{i}", {"status": "info"})
        assert len(logger.events) == 5

    def test_module_name_and_type(self, config, logger):
        m = ConcreteModule(config, logger)
        assert m.MODULE_NAME == "test_module"
        assert m.MODULE_TYPE == "attack"
