"""Block Scope looks up each uncached block hash once, concurrently, and stops after a failure."""

import os
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.widgets.BlockMatchWidget as block_match_module  # noqa: E402
from mcrit_plugin.core.McritInterface import McritInterface  # noqa: E402
from mcrit_plugin.ui_qt.widgets.BlockMatchWidget import BlockMatchWidget  # noqa: E402


def _widget(lookup, cached=None):
    interface = McritInterface.__new__(McritInterface)
    interface.parent = SimpleNamespace(
        blockhash_matches=dict(cached or {}), local_widget=MagicMock(), mcrit_interface=interface
    )
    interface._switch_lock = threading.Lock()
    interface._server_generation = 0
    interface.mcrit_client = SimpleNamespace(getMatchesForPicBlockHash=lookup)
    widget = BlockMatchWidget.__new__(BlockMatchWidget)
    widget.parent = interface.parent
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


def test_lookups_stop_once_the_cursor_left(monkeypatch):
    monkeypatch.setattr(block_match_module, "BLOCK_QUERY_WORKERS", 1)
    queried = []

    def lookup(block_hash):
        queried.append(block_hash)
        return [block_hash]

    widget = _widget(lookup)

    widget._lookupBlockHashes([1, 2, 3, 4], stop=lambda: len(queried) >= 2)

    assert queried == [1, 2]
    assert widget.parent.blockhash_matches == {1: [1], 2: [2]}, "skipped hashes stay uncached"


def test_block_matches_from_the_previous_server_are_not_cached():
    widget = _widget(lambda block_hash: [block_hash])
    interface = widget.parent.mcrit_interface
    storing = interface._storing

    @contextmanager
    def switch_first(generation):
        # the server changes after every lookup passed its own check, before the cache write
        interface._server_generation += 1
        with storing(generation) as current:
            yield current

    interface._storing = switch_first

    widget._lookupBlockHashes([1, 2])

    assert widget.parent.blockhash_matches == {}


class _LockCheckedDict(dict):
    def __init__(self, lock):
        super().__init__()
        self.lock = lock

    def __setitem__(self, key, value):
        assert self.lock.locked()
        super().__setitem__(key, value)

    def update(self, *args, **kwargs):
        assert self.lock.locked()
        super().update(*args, **kwargs)


def test_block_matches_are_cached_under_the_switch_lock():
    widget = _widget(lambda block_hash: [block_hash])
    widget.parent.blockhash_matches = _LockCheckedDict(widget.parent.mcrit_interface._switch_lock)

    widget._lookupBlockHashes([1, 2])

    assert widget.parent.blockhash_matches == {1: [1], 2: [2]}
