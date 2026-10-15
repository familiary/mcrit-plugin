"""Tests for the bundled McritClient (mcrit_plugin/core/minimcrit/client/McritClient.py).

The tests focus on the timeout/helper-request plumbing that ties together the
``mcrit_request_timeout`` setting and the actual ``requests`` calls. This is
what reviewer feedback flagged as a potential no-op; the tests pin the
behavior so it cannot regress silently.
"""

import datetime
from unittest.mock import MagicMock

import pytest
import requests

from mcrit_plugin.core.minimcrit.client.McritClient import (
    DEFAULT_TIMEOUT,
    JobFailedError,
    JobTerminatedError,
    McritClient,
    McritNotFound,
    McritServerError,
    McritUnauthorized,
    handle_response,
)
from mcrit_plugin.core.minimcrit.queue.LocalQueue import Job


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
            recorded.append((method, url, kwargs))
            return _make_response()

        monkeypatch.setattr(client, "_request", fake_request)
        client.setTimeout(3)

        # Each helper must call its session's <verb> via _request.
        client._get("http://example/get")
        client._post("http://example/post")
        client._put("http://example/put")
        client._delete("http://example/delete")

        verbs = [method.__name__ for method, _, _ in recorded]
        assert verbs == ["get", "post", "put", "delete"]
        assert all(method.__self__ is client._session for method, _, _ in recorded)


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

    def test_the_queue_count_uses_the_same_selectors(self, client, monkeypatch):
        captured = {}

        def fake_get(url, **kwargs):
            captured["url"] = url
            return _make_response(json_data={"status": "successful", "data": {"count": 3}})

        monkeypatch.setattr(client, "_get", fake_get)

        count = client.getQueueCount(method="getMatchesForSample", state="finished", sample_ids=[1])

        assert count == 3
        assert captured["url"].endswith(
            "/jobs/count?method=getMatchesForSample&state=finished&sample_ids=1"
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


def _response(status_code, body, url="http://example.test:8000/x"):
    """A real requests.Response with the given raw body."""
    response = requests.Response()
    response.status_code = status_code
    response._content = body
    response.url = url
    return response


class _Session:
    """Records each request and answers it with a canned response."""

    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def _record(self, method):
        def call(url, **kwargs):
            self.calls.append((method, url, kwargs))
            return self.answer

        return call

    def __getattr__(self, method):
        return self._record(method.upper())

    def sent_url(self):
        method, url, kwargs = self.calls[-1]
        return requests.Request(method, url, params=kwargs.get("params")).prepare().url


def _recording(client, answer=None):
    if answer is None:
        answer = _response(200, b'{"status": "successful", "data": {}}')
    session = _Session(answer)
    client._session = session
    return session


class TestNonJsonAnswers:
    @pytest.mark.parametrize("status", [200, 202])
    @pytest.mark.parametrize("body", [b"<html>login</html>", b""])
    def test_a_2xx_that_is_not_json_is_a_failed_answer(self, status, body, caplog):
        response = _response(status, body)

        assert handle_response(response) is None
        assert handle_response(response, raise_client_errors=True) is None
        with pytest.raises(McritServerError) as raised:
            handle_response(response, raise_server_errors=True)
        assert raised.value.status_code == status
        assert raised.value.message == ""
        assert "body that is not JSON" in caplog.text

    def test_a_2xx_whose_body_is_no_dict_is_a_failed_answer(self):
        response = _response(200, b'["successful"]')

        assert handle_response(response) is None
        with pytest.raises(McritServerError):
            handle_response(response, raise_server_errors=True)


def _job(result=None, terminated=False, attempts_left=1, **extra):
    data = {
        "result": result,
        "terminated": terminated,
        "attempts_left": attempts_left,
        "finished_at": None,
        **extra,
    }
    return Job(data, None)


class TestAwaitResult:
    def test_a_job_without_a_result_raises_job_failed(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "getJobData", lambda job_id: _job(attempts_left=0, last_error="out of memory")
        )
        client.getResult = MagicMock()

        with pytest.raises(JobFailedError) as raised:
            client.awaitResult("abc", sleep_time=0)

        assert raised.value.job_id == "abc"
        assert raised.value.last_error == "out of memory"
        assert str(raised.value) == "job abc failed: out of memory"
        client.getResult.assert_not_called()

    def test_a_job_that_never_recorded_an_error_has_none(self, client, monkeypatch):
        monkeypatch.setattr(client, "getJobData", lambda job_id: _job(attempts_left=0))

        with pytest.raises(JobFailedError) as raised:
            client.awaitResult("abc", sleep_time=0)

        assert raised.value.last_error is None
        assert str(raised.value) == "job abc failed"

    def test_a_terminated_job_still_raises_job_terminated(self, client, monkeypatch):
        monkeypatch.setattr(client, "getJobData", lambda job_id: _job(terminated=True))

        with pytest.raises(JobTerminatedError):
            client.awaitResult("abc", sleep_time=0)

    def test_a_finished_job_answers_its_result(self, client, monkeypatch):
        monkeypatch.setattr(client, "getJobData", lambda job_id: _job(result="r1"))
        client.getResult = MagicMock(return_value={"matches": []})

        assert client.awaitResult("abc", sleep_time=0) == {"matches": []}
        client.getResult.assert_called_once_with("r1", compact=False)


class TestModifyRequests:
    def test_modify_family_sends_json_with_actors(self, client):
        session = _recording(client)

        client.modifyFamily(3, family_name="emotet", actors=("TA542",))

        method, url, kwargs = session.calls[-1]
        assert (method, url) == ("PUT", "http://example.test:8000/families/3")
        assert kwargs["json"] == {"family_name": "emotet", "actors": ["TA542"]}
        assert "data" not in kwargs

    def test_an_empty_actor_list_clears_them(self, client):
        session = _recording(client)

        client.modifyFamily(3, actors=[])

        assert session.calls[-1][2]["json"] == {"actors": []}

    def test_modify_family_answers_the_response_in_raw_mode(self):
        client = McritClient(mcrit_server="http://example.test:8000", raw_responses=True)
        answer = _response(200, b'{"status": "successful", "data": {}}')
        _recording(client, answer)

        assert client.modifyFamily(3, family_name="emotet") is answer

    def test_modify_sample_sends_the_fields_as_form_data(self, client):
        session = _recording(client)

        client.modifySample(4, version="1.0")

        method, url, kwargs = session.calls[-1]
        assert (method, url) == ("PUT", "http://example.test:8000/samples/4")
        assert kwargs["data"] == {"version": "1.0"}

    @pytest.mark.parametrize(
        "call, path",
        [
            (
                lambda client: client.requestMatchesForUnmappedBinary(
                    b"MZ", disassemble_locally=False
                ),
                "/query/binary",
            ),
            (
                lambda client: client.requestMatchesForMappedBinary(
                    b"MZ", 0x400000, disassemble_locally=False
                ),
                "/query/binary/mapped/4194304",
            ),
        ],
    )
    def test_binary_queries_send_the_binary_as_the_body(self, client, call, path):
        session = _recording(client)

        call(client)

        method, url, kwargs = session.calls[-1]
        assert (method, url) == ("POST", "http://example.test:8000" + path)
        assert kwargs["data"] == b"MZ"


class TestTwoStageMatchingKnobs:
    KNOBS = {"shortlist_size": 500, "band_df_cutoff": 2000, "preset": "hunt"}

    @pytest.mark.parametrize(
        "call",
        [
            lambda client, **knobs: client.requestMatchesForSmdaReport(MagicMock(), **knobs),
            lambda client, **knobs: client.requestMatchesForSample(42, **knobs),
            lambda client, **knobs: client.getMatchesForSmdaFunction(MagicMock(), **knobs),
            lambda client, **knobs: client.requestMatchesForUnmappedBinary(
                b"MZ", disassemble_locally=False, **knobs
            ),
            lambda client, **knobs: client.requestMatchesForMappedBinary(
                b"MZ", 0, disassemble_locally=False, **knobs
            ),
        ],
    )
    def test_the_matching_requests_pass_the_knobs(self, client, call):
        session = _recording(client)

        call(client, **self.KNOBS)
        assert self.KNOBS.items() <= session.calls[-1][2]["params"].items()
        call(client)
        assert not set(self.KNOBS) & set(session.calls[-1][2]["params"])

    @pytest.mark.parametrize(
        "call",
        [
            lambda client, **knobs: client.requestMatchesForSampleVs(42, 43, **knobs),
            lambda client, **knobs: client.requestMatchesCross([42, 43], **knobs),
        ],
    )
    def test_sample_comparisons_take_no_shortlist(self, client, call):
        session = _recording(client)

        call(client, band_df_cutoff=2000, preset="identification")

        params = session.calls[-1][2]["params"]
        assert params["band_df_cutoff"] == 2000 and params["preset"] == "identification"
        with pytest.raises(TypeError):
            call(client, shortlist_size=500)

    def test_a_locally_disassembled_binary_keeps_the_knobs(self, client, monkeypatch):
        import mcrit_plugin.core.minimcrit.client.McritClient as module

        report = MagicMock(status="ok")
        monkeypatch.setattr(
            module, "Disassembler", lambda: MagicMock(disassembleUnmappedBuffer=lambda b: report)
        )
        session = _recording(client)

        client.requestMatchesForUnmappedBinary(b"MZ", **self.KNOBS)

        assert session.calls[-1][1] == "http://example.test:8000/query"
        assert session.calls[-1][2]["params"] == {"force_recalculation": False, **self.KNOBS}


class TestQueryStringEncoding:
    def test_the_job_count_filter_is_encoded(self, client):
        session = _recording(client, _response(200, b'{"status": "successful", "data": []}'))

        client.getJobCount(filter="a&b c")

        assert session.sent_url() == "http://example.test:8000/jobs?filter=a%26b+c"

    def test_queue_deletion_criteria_are_encoded(self, client):
        session = _recording(client)

        client.deleteQueueData(
            method="getMatchesForSample&x",
            created_before=datetime.datetime(2026, 10, 1, 12, 30),
        )

        assert session.sent_url() == (
            "http://example.test:8000/jobs/?method=getMatchesForSample%26x"
            "&created_before=2026-10-01T12%3A30%3A00"
        )


class TestRawFunctionLookups:
    def test_get_function_by_id_hands_back_a_failed_answer_in_raw_mode(self):
        client = McritClient(
            mcrit_server="http://example.test:8000",
            raw_responses=True,
            raise_client_errors=True,
        )
        answer = _response(404, b'{"status": "failed", "data": {"message": "no such function"}}')
        _recording(client, answer)

        assert client.getFunctionById(5) is answer


def test_the_session_pools_enough_connections_for_concurrent_requests():
    from mcrit_plugin.core.minimcrit.client.McritClient import SESSION_POOL_SIZE, McritClient

    client = McritClient("https://mcrit.example/api/")

    adapter = client._session.get_adapter("https://mcrit.example/api/status")
    assert adapter._pool_maxsize == SESSION_POOL_SIZE
    assert SESSION_POOL_SIZE > 10
