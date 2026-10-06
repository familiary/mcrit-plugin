"""Block Scope looks up each uncached block hash once, concurrently, and stops after a failure."""

import os
import threading
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.widgets.BlockMatchWidget as block_match_module  # noqa: E402
from mcrit_plugin.ui_qt.widgets.BlockMatchWidget import BlockMatchWidget  # noqa: E402


def _widget(lookup, cached=None):
    widget = BlockMatchWidget.__new__(BlockMatchWidget)
    widget.parent = SimpleNamespace(
        blockhash_matches=dict(cached or {}),
        mcrit_interface=SimpleNamespace(getMatchesForPicBlockHash=lookup),
    )
    return widget


def test_each_uncached_hash_is_queried_once():
    queried = []
    lock = threading.Lock()

    def lookup(block_hash):
        with lock:
            queried.append(block_hash)
        return [block_hash]

    widget = _widget(lookup, cached={1: ["cached"]})

    widget._lookupBlockHashes([1, 2, 3, 2, 3])

    assert sorted(queried) == [2, 3]
    assert widget.parent.blockhash_matches == {1: ["cached"], 2: [2], 3: [3]}


def test_lookups_run_concurrently():
    both_started = threading.Barrier(2, timeout=5)

    def lookup(block_hash):
        both_started.wait()
        return [block_hash]

    widget = _widget(lookup)

    widget._lookupBlockHashes([1, 2])

    assert widget.parent.blockhash_matches == {1: [1], 2: [2]}


def test_a_failed_lookup_stays_uncached_and_stops_the_rest(monkeypatch):
    monkeypatch.setattr(block_match_module, "BLOCK_QUERY_WORKERS", 1)
    queried = []

    def lookup(block_hash):
        queried.append(block_hash)
        return None if block_hash == 2 else [block_hash]

    widget = _widget(lookup)

    widget._lookupBlockHashes([1, 2, 3, 4])

    assert queried == [1, 2]
    assert widget.parent.blockhash_matches == {1: [1]}
