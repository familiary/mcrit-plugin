"""While a request runs off the UI thread the widgets stay usable; an answer that arrives after
the view moved on must not be shown."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.QtShim as QtShim  # noqa: E402
import mcrit_plugin.ui_qt.widgets.BlockMatchWidget as BlockMatchWidgetModule  # noqa: E402
from mcrit_plugin.core.config import McritConfig  # noqa: E402
from mcrit_plugin.ui_qt.ClassCollection import ClassCollection  # noqa: E402


class _DeferredBackend:
    """Holds each request's on_done until the test answers it."""

    def __init__(self):
        self.pending = []

    def run_request(self, title, work, on_done):
        self.pending.append(lambda: on_done(work()))


@pytest.fixture(scope="module")
def cc():
    QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    return ClassCollection(QtShim, None)


def test_block_scope_shows_only_the_latest_block_size(cc, monkeypatch):
    backend = _DeferredBackend()
    cc.backend = backend
    function = SimpleNamespace(offset=0x1000, num_instructions=20)
    session = SimpleNamespace(
        cc=cc,
        config=McritConfig("0.0.0"),
        current_function=0x1000,
        current_block=0x1000,
        local_smda_report=SimpleNamespace(getFunction=lambda offset: function),
        family_infos=None,
        sample_infos=None,
        blockhash_matches={},
        mcrit_interface=SimpleNamespace(getMatchesForPicBlockHash=lambda block_hash: []),
    )
    widget = BlockMatchWidgetModule.BlockMatchWidget(session)
    monkeypatch.setattr(
        BlockMatchWidgetModule.FunctionCfgMatcher,
        "getPicBlockHashesForFunction",
        lambda report, smda_function, min_size: [{"hash": min_size, "offset": 0x1000}],
    )
    monkeypatch.setattr(widget, "_fetch_remote_cache", lambda: True)
    shown = []
    monkeypatch.setattr(widget, "_showBlockMatches", lambda pbh: shown.append(pbh[0]["hash"]))

    widget.sb_blocksize_threshold.setValue(4)
    widget.updateViewWithCurrentBlock()
    widget.sb_blocksize_threshold.setValue(8)
    widget.updateViewWithCurrentBlock()
    for answer in reversed(backend.pending):
        answer()

    assert shown == [8]
