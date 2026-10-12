"""After Convert, the family and sample lists download once, and the family chooser for an unknown
sample opens when they are here."""

import os
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from mcrit_plugin.ui_qt.widgets.MainWidget import MainWidget  # noqa: E402


class _Backend:
    def __init__(self):
        self.pending = []

    def run_request(self, title, work, on_done):
        self.pending.append((work, on_done))


def _main_widget(remote_sample_entry):
    downloads = []
    widget = SimpleNamespace(
        cc=SimpleNamespace(backend=_Backend()),
        parent=SimpleNamespace(
            local_smda_report=None,
            remote_sample_entry=remote_sample_entry,
            getRemoteSampleInformation=lambda: downloads.append(1) or True,
            local_widget=MagicMock(),
        ),
        exportSmdaAction=MagicMock(),
        uploadSmdaAction=MagicMock(),
        buildYaraStringAction=MagicMock(),
        getMatchResultAction=MagicMock(),
        _building=False,
        _enableMatchWidgets=MagicMock(),
        _askSmdaInfo=MagicMock(),
    )
    for name in ("_applyConvertedReport", "_downloadListsForChooser"):
        setattr(widget, name, types.MethodType(getattr(MainWidget, name), widget))
    return widget, downloads


def _answer_all(backend):
    while backend.pending:
        work, on_done = backend.pending.pop(0)
        on_done(work())


def test_an_unknown_sample_downloads_the_lists_once_for_the_chooser():
    widget, downloads = _main_widget(remote_sample_entry=None)

    widget._applyConvertedReport(SimpleNamespace(family="", version="", is_library=False))

    assert len(widget.cc.backend.pending) == 1
    assert widget._building
    _answer_all(widget.cc.backend)
    assert downloads == [1]
    widget._askSmdaInfo.assert_called_once()


def test_a_known_sample_downloads_the_lists_in_the_background():
    remote = SimpleNamespace(family="emotet", version="1", is_library=False)
    widget, downloads = _main_widget(remote_sample_entry=remote)

    widget._applyConvertedReport(SimpleNamespace(family="", version="", is_library=False))
    _answer_all(widget.cc.backend)

    assert downloads == [1]
    assert not widget._building
    widget._askSmdaInfo.assert_not_called()
    assert widget.parent.local_smda_report.family == "emotet"


def test_a_failed_list_request_lets_the_next_convert_try_again():
    widget, _downloads = _main_widget(remote_sample_entry=None)

    def unreachable():
        raise RuntimeError("can't start new thread")

    widget.parent.getRemoteSampleInformation = unreachable
    widget._applyConvertedReport(SimpleNamespace(family="", version="", is_library=False))
    work, _on_done = widget.cc.backend.pending.pop()

    with pytest.raises(RuntimeError):
        work()
    assert not widget._building
