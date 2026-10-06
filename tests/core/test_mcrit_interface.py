"""Tests for the McritInterface logic that runs without a disassembler or an MCRIT server."""

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from mcrit_plugin.core.McritInterface import McritInterface


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

        def job(parameters):
            return SimpleNamespace(parameters=parameters)

        wanted = job("getMatchesForSample(23, 2)")
        interface.mcrit_client.getQueueData.return_value = [
            wanted,
            job("getMatchesForSample(230, 2)"),
            job("updateMinHashesForSample(23)"),
        ]

        assert interface.queryJobs(sample_id=23) == [wanted]
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
