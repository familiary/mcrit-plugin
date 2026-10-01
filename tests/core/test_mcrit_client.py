"""Tests for the bundled McritClient (mcrit_plugin/core/minimcrit/client/McritClient.py).

The tests focus on the timeout/helper-request plumbing that ties together the
``mcrit_request_timeout`` setting and the actual ``requests`` calls. This is
what reviewer feedback flagged as a potential no-op; the tests pin the
behavior so it cannot regress silently.
"""

from unittest.mock import MagicMock

import pytest

from mcrit_plugin.core.minimcrit.client.McritClient import (
    DEFAULT_TIMEOUT,
    McritClient,
    McritNotFound,
    McritServerError,
    McritUnauthorized,
    handle_response,
)


@pytest.fixture
def client():
    """Fixture providing a McritClient instance for testing."""
    return McritClient(mcrit_server="http://example.test:8000")


def _make_response(status_code=200, json_data=None):
    """Create a mock HTTP response object.

    Args:
        status_code: HTTP status code (default 200).
        json_data: Dictionary to return from response.json() call.

    Returns:
        Mock response object configured with the given parameters.
    """
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data or {"status": "successful", "data": {}}
    return response


class TestSetTimeout:
    def test_default_timeout_bounds_only_the_connect(self, client):
        assert client.timeout == DEFAULT_TIMEOUT == (10, None)

    def test_set_positive_timeout(self, client):
        client.setTimeout(15)
        assert client.timeout == 15

    def test_set_string_timeout_is_coerced(self, client):
        client.setTimeout("20")
        assert client.timeout == 20

    def test_set_none_clears_timeout(self, client):
        client.setTimeout(15)
        client.setTimeout(None)
        assert client.timeout is None

    def test_set_zero_timeout_disables(self, client):
        client.setTimeout(0)
        assert client.timeout is None

    def test_set_negative_timeout_disables(self, client):
        client.setTimeout(-5)
        assert client.timeout is None

    def test_set_non_numeric_string_raises(self, client):
        with pytest.raises(ValueError):
            client.setTimeout("not-a-number")


class TestRequestHelpers:
    def test_request_injects_configured_timeout(self, client):
        client.setTimeout(7)
        method = MagicMock(return_value=_make_response())
        client._request(method, "http://x", headers={"a": "b"})
        method.assert_called_once_with("http://x", headers={"a": "b"}, timeout=7)

    def test_request_preserves_explicit_timeout(self, client):
        client.setTimeout(7)
        method = MagicMock(return_value=_make_response())
        client._request(method, "http://x", timeout=99)
        method.assert_called_once_with("http://x", timeout=99)

    def test_request_uses_the_default_timeout_when_unset(self, client):
        method = MagicMock(return_value=_make_response())
        client._request(method, "http://x")
        method.assert_called_once_with("http://x", timeout=DEFAULT_TIMEOUT)

    def test_get_post_put_delete_route_through_request(self, client, monkeypatch):
        recorded = []

        def fake_request(method, url, **kwargs):
            recorded.append((method.__name__, url, kwargs))
            return _make_response()

        monkeypatch.setattr(client, "_request", fake_request)
        client.setTimeout(3)

        # Each helper must call its corresponding requests.<verb> via _request.
        client._get("http://example/get")
        client._post("http://example/post")
        client._put("http://example/put")
        client._delete("http://example/delete")

        verbs = [name for name, _, _ in recorded]
        assert verbs == ["get", "post", "put", "delete"]


class TestSampleGroupOnly:
    def test_param_omitted_when_default(self, client):
        params = client._getMatchingRequestParams()
        assert "sample_group_only" not in params

    def test_param_included_when_truthy(self, client):
        params = client._getMatchingRequestParams(sample_group_only=True)
        assert params["sample_group_only"] is True

    def test_get_matches_for_smda_function_default_omits_param(self, client, monkeypatch):
        captured = {}

        def fake_post(url, **kwargs):
            captured["kwargs"] = kwargs
            return _make_response()

        monkeypatch.setattr(client, "_post", fake_post)

        smda_report = MagicMock()
        smda_report.toDict.return_value = {}

        client.getMatchesForSmdaFunction(smda_report)

        assert "sample_group_only" not in captured["kwargs"]["params"]

    def test_request_matches_for_smda_report_default_omits_param(self, client, monkeypatch):
        captured = {}

        def fake_post(url, **kwargs):
            captured["kwargs"] = kwargs
            return _make_response()

        monkeypatch.setattr(client, "_post", fake_post)

        smda_report = MagicMock()
        smda_report.toDict.return_value = {}

        client.requestMatchesForSmdaReport(smda_report)

        assert "sample_group_only" not in captured["kwargs"]["params"]

    def test_request_matches_for_sample_default_omits_param(self, client, monkeypatch):
        captured = {}

        def fake_get(url, **kwargs):
            captured["kwargs"] = kwargs
            return _make_response()

        monkeypatch.setattr(client, "_get", fake_get)

        client.requestMatchesForSample(42)

        assert "sample_group_only" not in captured["kwargs"]["params"]

    @pytest.mark.parametrize(
        "call",
        [
            lambda client: client.getMatchesForSmdaFunction(MagicMock(), sample_group_only=True),
            lambda client: client.requestMatchesForSmdaReport(MagicMock(), sample_group_only=True),
            lambda client: client.requestMatchesForSample(42, sample_group_only=True),
            lambda client: client.requestMatchesForSampleVs(42, 43, sample_group_only=True),
        ],
    )
    def test_only_the_cross_compare_takes_it(self, client, call):
        with pytest.raises(TypeError):
            call(client)

    def test_request_matches_cross_passes_sample_group_only(self, client, monkeypatch):
        captured = {}

        def fake_get(url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return _make_response()

        monkeypatch.setattr(client, "_get", fake_get)

        client.requestMatchesCross([42, 43], sample_group_only=True)

        assert captured["url"].endswith("/matches/sample/cross/42,43")
        assert captured["kwargs"]["params"]["sample_group_only"] is True


class TestSelectors:
    def test_job_selectors_are_url_encoded(self, client, monkeypatch):
        captured = {}

        def fake_get(url, **kwargs):
            captured["url"] = url
            return _make_response(json_data={"status": "successful", "data": []})

        monkeypatch.setattr(client, "_get", fake_get)

        client.getQueueData(
            method="getMatchesForSample", filter="a b", sample_ids=[1, 2], job_ids=["x"]
        )

        assert captured["url"].endswith(
            "/jobs/?method=getMatchesForSample&filter=a+b&sample_ids=1,2&job_ids=x"
        )

    def test_unique_blocks_send_only_the_given_parameters(self, client, monkeypatch):
        captured = []

        def fake_get(url, **kwargs):
            captured.append(kwargs["params"])
            return _make_response()

        monkeypatch.setattr(client, "_get", fake_get)

        client.requestUniqueBlocksForFamily(3)
        client.requestUniqueBlocksForSamples([1, 2], covers_required=5, min_instructions=4)

        assert captured == [{}, {"covers_required": 5, "min_instructions": 4}]


class TestHandleResponse:
    def test_successful_response_returns_data(self):
        response = _make_response(200, {"status": "successful", "data": {"v": 1}})
        assert handle_response(response) == {"v": 1}

    def test_status_code_500_returns_none(self):
        response = _make_response(500, {})
        assert handle_response(response) is None

    def test_unsuccessful_status_returns_none(self):
        response = _make_response(200, {"status": "failed"})
        assert handle_response(response) is None

    def test_404_returns_none(self):
        response = _make_response(404, {})
        assert handle_response(response) is None


class TestRaisingModes:
    def test_by_default_every_failure_answers_none(self, client, monkeypatch):
        monkeypatch.setattr(client, "_get", lambda url, **kwargs: _make_response(404, {}))
        assert client.getSampleById(1) is None

    def test_client_errors_raise_their_class(self, monkeypatch):
        client = McritClient(mcrit_server="http://example.test:8000", raise_client_errors=True)
        monkeypatch.setattr(
            client,
            "_get",
            lambda url, **kwargs: _make_response(
                404, {"status": "failed", "data": {"message": "no sample"}}
            ),
        )
        with pytest.raises(McritNotFound, match="no sample"):
            client.getSampleById(1)

    def test_server_errors_raise_in_their_mode(self):
        with pytest.raises(McritServerError):
            handle_response(_make_response(500, {}), raise_server_errors=True)
        with pytest.raises(McritServerError):
            handle_response(_make_response(200, {"status": "failed"}), raise_server_errors=True)

    def test_401_and_403_are_unauthorized(self):
        for status in (401, 403):
            with pytest.raises(McritUnauthorized):
                handle_response(_make_response(status, {}), raise_client_errors=True)
