"""Tests for the McritInterface logic that runs without a disassembler or an MCRIT server."""

import json
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from mcrit_plugin.core.McritInterface import McritInterface
from mcrit_plugin.core.minimcrit.queue.LocalQueue import Job


class _FakeBinaryInfo:
    """Fake BinaryInfo for testing architecture detection."""

    def __init__(self, architecture):
        """Initialize with an architecture string."""
        self.architecture = architecture


def _make_interface(timeout=10):
    """Build a McritInterface instance bypassing __init__ to avoid IDA-specific setup.

    Args:
        timeout: MCRIT request timeout in seconds.

    Returns:
        A partially initialized McritInterface for testing.
    """
    inst = McritInterface.__new__(McritInterface)
    inst.parent = SimpleNamespace(
        local_widget=MagicMock(),
        config=SimpleNamespace(MCRIT_REQUEST_TIMEOUT=timeout),
        remote_sample_id=23,
        function_matches={},
        function_id_to_offset={},
        matched_function_entries=None,
    )
    inst.config = inst.parent.config
    inst._mcrit_server = "http://127.0.0.1:8000"
    inst._cache_lock = threading.Lock()
    inst._remote_info_lock = threading.Lock()
    inst._check_id = 0
    inst.mcrit_client = MagicMock()
    return inst


@pytest.mark.parametrize(
    "architecture, expected",
    [
        ("x86", "intel"),
        ("X86_64", "intel"),
        ("amd64", "intel"),
        ("i386", "intel"),
        ("intel", "intel"),
        ("AARCH64", "aarch64"),
        ("arm64", "aarch64"),
    ],
)
def test_select_smda_backend_known_arches(architecture, expected):
    interface = _make_interface()
    assert interface._select_smda_backend(_FakeBinaryInfo(architecture)) == expected


@pytest.mark.parametrize("architecture", ["riscv", "arm", "mips", "ppc", "powerpc64", "sparc"])
def test_select_smda_backend_unknown_returns_none(architecture):
    # SMDA only offers intel, aarch64, cil and dalvik; any other name would leave the
    # Disassembler without a backend instead of raising, so it must answer None here.
    interface = _make_interface()
    assert interface._select_smda_backend(_FakeBinaryInfo(architecture)) is None


def test_select_smda_backend_handles_none_architecture():
    interface = _make_interface()
    assert interface._select_smda_backend(_FakeBinaryInfo(None)) is None


def test_select_smda_backend_handles_empty_string():
    interface = _make_interface()
    assert interface._select_smda_backend(_FakeBinaryInfo("")) is None


@pytest.mark.parametrize("timeout, expected", [(30, 30), (0, None)])
def test_the_configured_timeout_reaches_the_client(timeout, expected):
    config = SimpleNamespace(
        MCRIT_SERVER="http://127.0.0.1:8000",
        MCRIT_REQUEST_TIMEOUT=timeout,
        MCRITWEB_API_TOKEN="",
        MCRITWEB_USERNAME="",
    )

    interface = McritInterface(SimpleNamespace(config=config), backend=None)

    assert interface.mcrit_client.timeout == expected


class TestCheckConnectionImpl:
    def test_returns_version_on_success(self):
        interface = _make_interface()
        interface.mcrit_client.getVersion.return_value = "1.2.3"
        result = interface._check_connection_impl()
        assert result == ("1.2.3", None)

    def test_returns_exception_on_failure(self):
        interface = _make_interface()
        boom = RuntimeError("network down")
        interface.mcrit_client.getVersion.side_effect = boom
        version, err = interface._check_connection_impl()
        assert version is None
        assert err is boom

    def test_logs_no_traceback_for_an_unreachable_server(self, capsys):
        interface = _make_interface()
        interface.mcrit_client.getVersion.side_effect = requests.exceptions.ConnectionError(
            "refused"
        )
        _version, err = interface._check_connection_impl()
        assert isinstance(err, requests.exceptions.ConnectionError)
        assert "Traceback" not in capsys.readouterr().err

    def test_logs_the_traceback_for_an_unexpected_error(self, capsys):
        interface = _make_interface()
        interface.mcrit_client.getVersion.side_effect = RuntimeError("plugin bug")
        interface._check_connection_impl()
        assert "Traceback" in capsys.readouterr().err


class TestQueryFunctionEntriesById:
    def test_returns_none_when_the_request_fails(self):
        interface = _make_interface()
        interface.mcrit_client.getFunctionsByIds.side_effect = TimeoutError("slow")

        assert interface.queryFunctionEntriesById([1, 2], with_label_only=True) is None
        assert interface.parent.matched_function_entries is None

    def test_returns_empty_dict_when_no_entry_qualifies(self):
        interface = _make_interface()
        interface.mcrit_client.getFunctionsByIds.return_value = {}

        assert interface.queryFunctionEntriesById([1], with_label_only=True) == {}

    def test_merges_entries_into_the_session(self):
        interface = _make_interface()
        entry = SimpleNamespace(function_labels=["evil"])
        interface.mcrit_client.getFunctionsByIds.return_value = {7: entry}

        assert interface.queryFunctionEntriesById([7]) == {7: entry}
        assert interface.parent.matched_function_entries == {7: entry}

    def test_leaves_a_dict_the_ui_is_iterating_unchanged(self):
        interface = _make_interface()
        old_entry = SimpleNamespace(function_labels=[])
        interface.parent.matched_function_entries = {1: old_entry}
        being_iterated = interface.parent.matched_function_entries
        interface.mcrit_client.getFunctionsByIds.return_value = {7: old_entry}

        interface.queryFunctionEntriesById([7])

        assert being_iterated == {1: old_entry}
        assert interface.parent.matched_function_entries == {1: old_entry, 7: old_entry}


class TestServerErrors:
    def test_a_rejected_upload_reports_failure_without_a_traceback(self, capsys):
        interface = _make_interface()
        interface.mcrit_client.addReport.return_value = None

        interface.uploadReport(MagicMock())

        interface.parent.local_widget.updateActivityInfo.assert_called_with("Upload failed.")
        assert "Traceback" not in capsys.readouterr().err

    def test_a_rejected_job_query_reports_failure(self):
        interface = _make_interface()
        interface.mcrit_client.getQueueData.return_value = None

        assert interface.queryJobs(sample_id=23) is None
        interface.parent.local_widget.updateActivityInfo.assert_called_with("Job query failed.")

    def test_jobs_of_a_sample_are_narrowed_by_the_server_and_checked_exactly(self):
        interface = _make_interface()

        def job(method, *args, **kwargs):
            # as MCRIT stores a job: keyword arguments by name, positional ones as "0", "1", ...
            params = dict(kwargs)
            params.update({str(index): value for index, value in enumerate(args)})
            return Job({"payload": {"method": method, "params": json.dumps(params)}}, None)

        wanted = [
            job("getMatchesForSample", 23, minhash_threshold=50),
            job("getMatchesForSampleVs", 5, 23),
            job("getMatchesForSampleVsGroup", 7, [5, 23]),
            job("getMatchesForSampleVs", "23", "5"),
        ]
        interface.mcrit_client.getQueueData.return_value = wanted + [
            job("getMatchesForSample", 230),
            job("getMatchesForSample", 50, minhash_threshold=23),
            job("getMatchesForSampleVs", 5, 230),
            job("updateMinHashesForSample", 23),
            job("getMatchesForSmdaReport", None, minhash_threshold=23),
        ]

        assert interface.queryJobs(sample_id=23) == wanted
        interface.mcrit_client.getQueueData.assert_called_once_with(filter="23")


class TestRemoteInformation:
    def test_the_lists_are_downloaded_once_by_whoever_asks_first(self):
        interface = _make_interface()
        interface.parent.family_infos = None
        interface.parent.sample_infos = None
        interface.mcrit_client.getFamilies.return_value = {1: MagicMock()}
        interface.mcrit_client.getSamples.return_value = {2: MagicMock()}

        assert interface.ensureRemoteInformation() is True
        assert interface.ensureRemoteInformation() is True
        assert interface.mcrit_client.getFamilies.call_count == 1
        assert interface.mcrit_client.getSamples.call_count == 1

    def test_a_failed_download_is_tried_again_on_the_next_ask(self):
        interface = _make_interface()
        interface.parent.family_infos = None
        interface.parent.sample_infos = None
        interface.mcrit_client.getFamilies.return_value = None
        interface.mcrit_client.getSamples.return_value = {2: MagicMock()}

        assert interface.ensureRemoteInformation() is False
        interface.mcrit_client.getFamilies.return_value = {1: MagicMock()}
        assert interface.ensureRemoteInformation() is True
        assert interface.mcrit_client.getSamples.call_count == 1


class TestQueryRemoteFunction:
    def _interface(self, sample_infos=None):
        interface = _make_interface()
        interface.parent.sample_infos = sample_infos
        entry = MagicMock(sample_id=5)
        interface.mcrit_client.getFunctionById.return_value = entry
        return interface, entry

    def test_the_sample_comes_from_the_downloaded_list(self):
        sample = object()
        interface, entry = self._interface(sample_infos={5: sample})

        assert interface.queryRemoteFunction(9) == (entry, entry.toSmdaFunction(), sample)
        interface.mcrit_client.getFunctionById.assert_called_once_with(9, with_xcfg=True)
        interface.mcrit_client.getSampleById.assert_not_called()

    def test_an_unlisted_sample_is_requested(self):
        sample = object()
        interface, entry = self._interface(sample_infos={})
        interface.mcrit_client.getSampleById.return_value = sample

        assert interface.queryRemoteFunction(9) == (entry, entry.toSmdaFunction(), sample)
        interface.mcrit_client.getSampleById.assert_called_once_with(5)

    def test_a_missing_function_or_sample_is_reported(self):
        interface, _entry = self._interface()
        interface.mcrit_client.getSampleById.return_value = None

        assert interface.queryRemoteFunction(9) is None
        interface.parent.local_widget.updateActivityInfo.assert_called_with(
            "Failed to fetch sample entry 5."
        )
        interface.mcrit_client.getFunctionById.return_value = None

        assert interface.queryRemoteFunction(9) is None
        interface.parent.local_widget.updateActivityInfo.assert_called_with(
            "Failed to fetch function entry 9."
        )

    def test_a_raising_request_keeps_its_reason(self):
        interface, _entry = self._interface()
        interface.mcrit_client.getFunctionById.side_effect = requests.exceptions.ReadTimeout()

        assert interface.queryRemoteFunction(9) is None
        interface.parent.local_widget.updateActivityInfo.assert_called_once_with(
            "Fetching function 9 for the graph viewer failed (request timed out)."
        )

    def test_a_cfg_that_cannot_be_read_is_reported_as_a_failed_fetch(self):
        interface, entry = self._interface(sample_infos={5: object()})
        entry.toSmdaFunction.side_effect = KeyError("xcfg")

        assert interface.queryRemoteFunction(9) is None
        interface.parent.local_widget.updateActivityInfo.assert_called_once_with(
            "Fetching function 9 for the graph viewer failed (unexpected KeyError: 'xcfg')."
        )


class TestReloadSettings:
    @staticmethod
    def _interface(server="http://127.0.0.1:8000/"):
        config = SimpleNamespace(
            MCRIT_SERVER=server,
            MCRIT_REQUEST_TIMEOUT=10,
            MCRITWEB_API_TOKEN="",
            MCRITWEB_USERNAME="",
        )
        parent = SimpleNamespace(
            config=config,
            local_widget=MagicMock(),
            remote_sample_id=None,
            remote_sample_entry=None,
            matching_report=None,
            matched_function_entries=None,
            function_matches={},
            blockhash_matches={},
            sample_infos=None,
            family_infos=None,
        )
        interface = McritInterface(parent, backend=None)
        interface.checkConnection = MagicMock()
        return interface, config

    def test_unchanged_settings_keep_the_client(self):
        interface, _config = self._interface()
        client = interface.mcrit_client

        interface.reloadSettings()

        assert interface.mcrit_client is client
        interface.checkConnection.assert_not_called()

    def test_a_changed_server_and_token_build_a_new_client_and_check_it(self):
        interface, config = self._interface()
        old_client = interface.mcrit_client
        config.MCRIT_SERVER = "https://mcrit.example.com/"
        config.MCRITWEB_API_TOKEN = "token"

        interface.reloadSettings()

        assert interface.mcrit_client is not old_client
        assert interface.mcrit_client.mcrit_server == "https://mcrit.example.com/"
        assert interface.mcrit_client.headers["apitoken"] == "token"
        assert interface.server == "https://mcrit.example.com/"
        interface.checkConnection.assert_called_once_with(async_=True)

    def test_recheck_checks_unchanged_settings_again_on_the_same_client(self):
        interface, _config = self._interface()
        client = interface.mcrit_client

        interface.reloadSettings(recheck=True)

        assert interface.mcrit_client is client
        interface.checkConnection.assert_called_once_with(async_=True)

    @pytest.mark.parametrize(
        "field, value",
        [
            ("remote_sample_id", 23),
            ("remote_sample_entry", object()),
            ("matching_report", object()),
            ("matched_function_entries", {7: object()}),
            ("function_matches", {0x401000: {}}),
            ("blockhash_matches", {1: []}),
            ("sample_infos", {}),
            ("family_infos", {}),
        ],
    )
    def test_a_new_server_waits_for_a_reopen_while_results_of_the_old_one_are_held(
        self, field, value
    ):
        interface, config = self._interface()
        client = interface.mcrit_client
        setattr(interface.parent, field, value)
        config.MCRIT_SERVER = "https://mcrit.example.com/"

        assert interface.reloadSettings() == "https://mcrit.example.com/"

        assert interface.mcrit_client is client
        assert interface.server == "http://127.0.0.1:8000/"
        interface.checkConnection.assert_not_called()

    def test_the_rest_of_the_settings_apply_while_the_new_server_waits(self):
        interface, config = self._interface()
        interface.parent.remote_sample_id = 23
        config.MCRIT_SERVER = "https://mcrit.example.com/"
        config.MCRITWEB_API_TOKEN = "token"

        assert interface.reloadSettings() == "https://mcrit.example.com/"
        assert interface.mcrit_client.headers["apitoken"] == "token"
        assert interface.server == "http://127.0.0.1:8000/"

        config.MCRITWEB_API_TOKEN = "token2"
        interface.reloadSettings()

        assert interface.mcrit_client.headers["apitoken"] == "token2"
        assert interface.checkConnection.call_count == 2


def test_a_check_that_answers_after_the_settings_changed_is_dropped():
    config = SimpleNamespace(
        MCRIT_SERVER="http://old:8000/",
        MCRIT_REQUEST_TIMEOUT=10,
        MCRITWEB_API_TOKEN="",
        MCRITWEB_USERNAME="",
        SERVER_IS_DEFAULT=False,
    )
    local_widget = MagicMock()
    interface = McritInterface(SimpleNamespace(config=config, local_widget=local_widget), None)
    old_client = interface.mcrit_client
    started = threading.Event()
    release = threading.Event()

    class _Backend:
        @staticmethod
        def run_on_ui_thread(func):
            func()

    interface.backend = _Backend()

    def slow_version():
        started.set()
        release.wait(5)
        return "1.0.0"

    old_client.getVersion = slow_version
    threads_before = set(threading.enumerate())
    interface.checkConnection(async_=True)
    assert started.wait(5)
    interface._buildClient(("http://new:8000/", 10, "", ""))
    release.set()
    for thread in set(threading.enumerate()) - threads_before:
        thread.join(5)

    assert not any(
        "successful" in call.args[0] for call in local_widget.updateActivityInfo.call_args_list
    )


def test_an_older_check_on_the_same_client_does_not_overwrite_a_newer_one():
    interface = _make_interface()
    interface.config.SERVER_IS_DEFAULT = False
    pending = []
    interface.backend = SimpleNamespace(run_on_ui_thread=lambda func: pending.append(func))
    interface.mcrit_client.getVersion.side_effect = [
        requests.exceptions.Timeout("slow"),
        "1.15.0",
    ]
    threads_before = set(threading.enumerate())

    interface.checkConnection(async_=True)
    for thread in set(threading.enumerate()) - threads_before:
        thread.join(5)
    interface.checkConnection(async_=True)
    for thread in set(threading.enumerate()) - threads_before:
        thread.join(5)
    for apply in reversed(pending):
        apply()

    messages = [
        call.args[0] for call in interface.parent.local_widget.updateActivityInfo.call_args_list
    ]
    assert messages[-1] == "Connection check successful!"
    assert not any("timed out" in message for message in messages)


@pytest.mark.parametrize(
    "method, args, request_name, field",
    [
        ("querySampleSha256", ("abc",), "getSampleBySha256", "remote_sample_entry"),
        ("queryAllFamilyEntries", (), "getFamilies", "family_infos"),
        ("queryAllSampleEntries", (), "getSamples", "sample_infos"),
    ],
)
def test_an_answer_from_a_replaced_client_is_not_stored(method, args, request_name, field):
    interface = _make_interface()
    interface.parent.remote_sample_entry = None
    interface.parent.family_infos = None
    interface.parent.sample_infos = None
    old_client = interface.mcrit_client

    def answer_after_the_swap(*_args, **_kwargs):
        interface.mcrit_client = MagicMock()
        return {1: "from the old server"}

    getattr(old_client, request_name).side_effect = answer_after_the_swap

    getattr(interface, method)(*args)

    assert getattr(interface.parent, field) is None


@pytest.mark.parametrize("server_is_default, hinted", [(True, True), (False, False)])
def test_a_failed_check_points_at_settings_only_while_no_server_is_set(server_is_default, hinted):
    interface = _make_interface()
    interface.config.SERVER_IS_DEFAULT = server_is_default
    interface.mcrit_client.getVersion.side_effect = requests.exceptions.ConnectionError("refused")

    interface.checkConnection()

    message = interface.parent.local_widget.updateActivityInfo.call_args_list[-1].args[0]
    assert message.startswith("Connection check failed (server unreachable).")
    assert ("Settings button" in message) == hinted
