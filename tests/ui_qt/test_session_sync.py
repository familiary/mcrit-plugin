"""The names McritSession finds and uploads when the database changed since conversion."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from mcrit_plugin.ui_qt.McritSession import McritSession


class _Session(SimpleNamespace):
    findUnsyncedFunctionNames = McritSession.findUnsyncedFunctionNames
    uploadUpdatedReport = McritSession.uploadUpdatedReport


def _session(report_names, current_names):
    functions = [
        SimpleNamespace(offset=offset, function_name=name) for offset, name in report_names
    ]
    session = _Session(
        local_smda_report=SimpleNamespace(getFunctions=lambda: iter(functions)),
        cc=SimpleNamespace(backend=SimpleNamespace(get_function_symbols=lambda: current_names)),
        mcrit_interface=MagicMock(),
    )
    return session, functions


def test_renamed_and_new_names_are_unsynced():
    session, _ = _session(
        [(0x10, "old"), (0x20, "kept"), (0x40, "")],
        {0x10: "new", 0x20: "kept", 0x40: "added"},
    )

    assert sorted(session.findUnsyncedFunctionNames()) == [
        (0x10, "old", "new"),
        (0x40, None, "added"),
    ]


def test_the_upload_patches_renamed_functions_into_the_report():
    session, functions = _session([(0x10, "old"), (0x20, "kept")], {0x10: "new", 0x20: "kept"})

    session.uploadUpdatedReport()

    assert [function.function_name for function in functions] == ["new", "kept"]
    session.mcrit_interface.uploadReport.assert_called_once_with(session.local_smda_report)
