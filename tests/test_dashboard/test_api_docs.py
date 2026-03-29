"""Tests for the CyberSim6 Dashboard API documentation module."""

import io
import json
import pytest

from cybersim.dashboard.api_docs import (
    OPENAPI_SPEC,
    get_openapi_spec,
    serve_swagger_ui,
)


class TestGetOpenAPISpec:
    """Tests for get_openapi_spec()."""

    def test_returns_dict(self):
        spec = get_openapi_spec()
        assert isinstance(spec, dict)

    def test_returns_same_object_as_module_constant(self):
        assert get_openapi_spec() is OPENAPI_SPEC


class TestOpenAPISpecStructure:
    """Validate the OpenAPI 3.0 specification structure."""

    @pytest.fixture(autouse=True)
    def _load_spec(self):
        self.spec = get_openapi_spec()

    def test_openapi_version(self):
        assert self.spec["openapi"].startswith("3.0")

    def test_info_section(self):
        info = self.spec["info"]
        assert "title" in info
        assert "version" in info
        assert "description" in info

    def test_servers_defined(self):
        assert "servers" in self.spec
        assert len(self.spec["servers"]) >= 1
        assert "url" in self.spec["servers"][0]

    def test_tags_defined(self):
        assert "tags" in self.spec
        assert len(self.spec["tags"]) > 0
        for tag in self.spec["tags"]:
            assert "name" in tag
            assert "description" in tag

    def test_paths_defined(self):
        assert "paths" in self.spec
        assert len(self.spec["paths"]) > 0

    def test_components_schemas_defined(self):
        assert "components" in self.spec
        assert "schemas" in self.spec["components"]
        assert len(self.spec["components"]["schemas"]) > 0


class TestAllEndpointsDocumented:
    """Ensure every dashboard endpoint has documentation."""

    EXPECTED_PATHS = [
        "/",
        "/dashboard",
        "/api/events",
        "/api/stats",
        "/api/timeline",
        "/api/soc",
        "/api/attack-map",
        "/api/replay/sessions",
        "/api/replay/state",
        "/api/replay/load",
        "/api/replay/step",
        "/api/replay/reset",
        "/api/replay/live",
        "/api/docs",
        "/api/openapi.json",
    ]

    @pytest.fixture(autouse=True)
    def _load_spec(self):
        self.spec = get_openapi_spec()

    @pytest.mark.parametrize("path", EXPECTED_PATHS)
    def test_endpoint_documented(self, path):
        assert path in self.spec["paths"], f"Endpoint {path} is not documented"

    @pytest.mark.parametrize("path", EXPECTED_PATHS)
    def test_endpoint_has_get_method(self, path):
        assert "get" in self.spec["paths"][path], f"Endpoint {path} missing GET method"

    @pytest.mark.parametrize("path", EXPECTED_PATHS)
    def test_endpoint_has_summary(self, path):
        operation = self.spec["paths"][path]["get"]
        assert "summary" in operation, f"Endpoint {path} missing summary"
        assert len(operation["summary"]) > 0

    @pytest.mark.parametrize("path", EXPECTED_PATHS)
    def test_endpoint_has_responses(self, path):
        operation = self.spec["paths"][path]["get"]
        assert "responses" in operation, f"Endpoint {path} missing responses"
        assert "200" in operation["responses"], f"Endpoint {path} missing 200 response"

    @pytest.mark.parametrize("path", EXPECTED_PATHS)
    def test_endpoint_has_tags(self, path):
        operation = self.spec["paths"][path]["get"]
        assert "tags" in operation, f"Endpoint {path} missing tags"
        assert len(operation["tags"]) > 0

    def test_no_extra_undocumented_paths(self):
        documented = set(self.spec["paths"].keys())
        expected = set(self.EXPECTED_PATHS)
        assert documented == expected, (
            f"Mismatch between documented and expected paths. "
            f"Extra: {documented - expected}, Missing: {expected - documented}"
        )


class TestEndpointDetails:
    """Verify specific endpoint documentation details."""

    @pytest.fixture(autouse=True)
    def _load_spec(self):
        self.spec = get_openapi_spec()

    def test_events_has_module_parameter(self):
        params = self.spec["paths"]["/api/events"]["get"]["parameters"]
        names = [p["name"] for p in params]
        assert "module" in names

    def test_events_has_limit_parameter(self):
        params = self.spec["paths"]["/api/events"]["get"]["parameters"]
        names = [p["name"] for p in params]
        assert "limit" in names

    def test_replay_load_has_session_parameter(self):
        params = self.spec["paths"]["/api/replay/load"]["get"]["parameters"]
        names = [p["name"] for p in params]
        assert "session" in names

    def test_replay_load_session_is_required(self):
        params = self.spec["paths"]["/api/replay/load"]["get"]["parameters"]
        session_param = next(p for p in params if p["name"] == "session")
        assert session_param["required"] is True

    def test_replay_step_has_count_parameter(self):
        params = self.spec["paths"]["/api/replay/step"]["get"]["parameters"]
        names = [p["name"] for p in params]
        assert "count" in names

    def test_replay_load_has_error_responses(self):
        responses = self.spec["paths"]["/api/replay/load"]["get"]["responses"]
        assert "400" in responses
        assert "404" in responses

    def test_replay_step_has_400_response(self):
        responses = self.spec["paths"]["/api/replay/step"]["get"]["responses"]
        assert "400" in responses


class TestComponentSchemas:
    """Verify component schemas are properly defined."""

    EXPECTED_SCHEMAS = [
        "Event",
        "Stats",
        "TimelineEntry",
        "SocSnapshot",
        "Incident",
        "Anomaly",
        "AuditTrailStatus",
        "AttackMap",
        "Technique",
        "ReplaySession",
        "ReplayState",
    ]

    @pytest.fixture(autouse=True)
    def _load_spec(self):
        self.schemas = get_openapi_spec()["components"]["schemas"]

    @pytest.mark.parametrize("schema_name", EXPECTED_SCHEMAS)
    def test_schema_exists(self, schema_name):
        assert schema_name in self.schemas, f"Schema {schema_name} not defined"

    @pytest.mark.parametrize("schema_name", EXPECTED_SCHEMAS)
    def test_schema_has_type(self, schema_name):
        assert "type" in self.schemas[schema_name]

    @pytest.mark.parametrize("schema_name", EXPECTED_SCHEMAS)
    def test_schema_has_properties(self, schema_name):
        assert "properties" in self.schemas[schema_name]
        assert len(self.schemas[schema_name]["properties"]) > 0


class TestSpecSerializable:
    """Ensure the spec can be serialized to JSON."""

    def test_json_serializable(self):
        spec = get_openapi_spec()
        result = json.dumps(spec)
        assert isinstance(result, str)
        assert len(result) > 100

    def test_json_roundtrip(self):
        spec = get_openapi_spec()
        serialized = json.dumps(spec)
        deserialized = json.loads(serialized)
        assert deserialized["openapi"] == spec["openapi"]
        assert deserialized["info"]["title"] == spec["info"]["title"]
        assert set(deserialized["paths"].keys()) == set(spec["paths"].keys())


class _FakeHandler:
    """Minimal mock of BaseHTTPRequestHandler for testing serve_swagger_ui."""

    def __init__(self):
        self.response_code = None
        self.headers = {}
        self.wfile = io.BytesIO()
        self._headers_ended = False

    def send_response(self, code):
        self.response_code = code

    def send_header(self, key, value):
        self.headers[key] = value

    def end_headers(self):
        self._headers_ended = True


class TestServeSwaggerUI:
    """Tests for serve_swagger_ui()."""

    def test_sends_200(self):
        handler = _FakeHandler()
        serve_swagger_ui(handler)
        assert handler.response_code == 200

    def test_content_type_html(self):
        handler = _FakeHandler()
        serve_swagger_ui(handler)
        assert "text/html" in handler.headers.get("Content-Type", "")

    def test_headers_ended(self):
        handler = _FakeHandler()
        serve_swagger_ui(handler)
        assert handler._headers_ended is True

    def test_body_contains_swagger_ui(self):
        handler = _FakeHandler()
        serve_swagger_ui(handler)
        body = handler.wfile.getvalue().decode("utf-8")
        assert "swagger-ui" in body.lower()

    def test_body_contains_openapi_json_url(self):
        handler = _FakeHandler()
        serve_swagger_ui(handler)
        body = handler.wfile.getvalue().decode("utf-8")
        assert "/api/openapi.json" in body

    def test_body_uses_only_local_assets(self):
        handler = _FakeHandler()
        serve_swagger_ui(handler)
        body = handler.wfile.getvalue().decode("utf-8")
        assert "cdn.jsdelivr" not in body
        assert "fonts.googleapis" not in body

    def test_body_is_valid_html(self):
        handler = _FakeHandler()
        serve_swagger_ui(handler)
        body = handler.wfile.getvalue().decode("utf-8")
        assert body.strip().startswith("<!DOCTYPE html>")
        assert "</html>" in body

    def test_body_contains_title(self):
        handler = _FakeHandler()
        serve_swagger_ui(handler)
        body = handler.wfile.getvalue().decode("utf-8")
        assert "CyberSim6" in body
