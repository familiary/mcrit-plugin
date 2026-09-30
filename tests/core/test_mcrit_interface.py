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


class _FakeSmdaFunction:
    """Fake SmdaFunction for testing."""

    def __init__(self, offset):
        """Initialize with a function offset."""
        self.offset = offset


class _FakeSmdaReport:
    """Fake SmdaReport for testing."""

    def __init__(self, functions):
        """Initialize with a list of functions."""
        self._functions = functions

    def getFunctions(self):
        """Return the list of functions."""
        return self._functions


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
