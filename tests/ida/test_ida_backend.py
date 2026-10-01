"""IdaBackend gives IDA the same error paths as Binary Ninja, and keeps MCRIT requests off IDA's main
thread."""

import importlib
import sys
import threading
import types
from unittest.mock import MagicMock

import pytest


class _Timers:
    """ida_kernwin's register_timer/unregister_timer; fire() runs the callback like IDA's loop does."""

    def __init__(self):
        self.callback = None
        self.unregistered = False

    def register(self, interval, callback):
        self.callback = callback
        return self

    def unregister(self, timer):
        self.unregistered = True
        self.callback = None
        return True

    def fire(self):
        if self.callback() == -1:
            self.callback = None


@pytest.fixture
def backend(monkeypatch):
    timers = _Timers()
    kernwin = types.SimpleNamespace(
        show_wait_box=MagicMock(),
        hide_wait_box=MagicMock(),
        warning=MagicMock(),
        register_timer=timers.register,
        unregister_timer=timers.unregister,
        timers=timers,
    )
    for name in ("ida_bytes", "ida_funcs", "ida_idaapi", "ida_nalt", "ida_undo", "idc"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)
    monkeypatch.setitem(sys.modules, "ida_hexrays", None)
    monkeypatch.delitem(sys.modules, "mcrit_plugin.ida.IdaBackend", raising=False)
    module = importlib.import_module("mcrit_plugin.ida.IdaBackend")
    return module.IdaBackend(), kernwin


def _finish_work(instance):
    """Wait until the workers have queued their results, as if the requests had answered."""
    instance._executor.shutdown(wait=True)
    instance._executor = None


def test_run_background_delivers_the_result_after_the_wait_box(backend):
    instance, kernwin = backend
    on_done = MagicMock()

    instance.run_background("Export", lambda: "report", on_done)

    kernwin.show_wait_box.assert_called_once_with("HIDECANCEL\nExport")
    kernwin.hide_wait_box.assert_called_once_with()
    on_done.assert_called_once_with("report")
    kernwin.warning.assert_not_called()


def test_run_background_reports_a_failure_instead_of_raising(backend):
    instance, kernwin = backend
    on_done = MagicMock()

    def work():
        raise RuntimeError("no code")

    instance.run_background("Export", work, on_done)

    kernwin.hide_wait_box.assert_called_once_with()
    kernwin.warning.assert_called_once_with("Export failed, see the Output window for details.")
    on_done.assert_not_called()


@pytest.mark.parametrize("answer, expected", [(1, True), (0, False)])
def test_ask_yes_no_passes_the_prompt_unchanged(backend, answer, expected):
    instance, kernwin = backend
    kernwin.ASKBTN_NO, kernwin.ASKBTN_YES = 0, 1
    kernwin.ask_yn = MagicMock(return_value=answer)

    assert instance.ask_yes_no("Upload 100% of the names?") is expected
    kernwin.ask_yn.assert_called_once_with(0, "Upload 100% of the names?")


def test_ask_save_file_passes_the_prompt_unchanged(backend):
    instance, kernwin = backend
    kernwin.ask_file = MagicMock(return_value="")

    assert instance.ask_save_file("sample.smda", "Save as") is None
    kernwin.ask_file.assert_called_once_with(1, "sample.smda", "Save as")


def test_run_request_runs_work_on_a_worker_and_on_done_on_the_timer(backend):
    instance, kernwin = backend
    on_done = MagicMock()
    worker = []

    def work():
        worker.append(threading.current_thread())
        return "answer"

    instance.run_request("Query", work, on_done)
    _finish_work(instance)
    on_done.assert_not_called()

    kernwin.timers.fire()

    assert worker[0] is not threading.current_thread()
    on_done.assert_called_once_with("answer")
    assert kernwin.timers.callback is None, "the timer stops once nothing is pending"


def test_run_request_reports_a_failure_by_its_title(backend):
    instance, kernwin = backend
    on_done = MagicMock()

    def work():
        raise RuntimeError("unreachable")

    instance.run_request("MCRIT: querying matches", work, on_done)
    _finish_work(instance)
    kernwin.timers.fire()

    kernwin.warning.assert_called_once_with(
        "MCRIT: querying matches failed, see the Output window for details."
    )
    on_done.assert_not_called()


def test_a_request_started_by_on_done_keeps_the_timer_running(backend):
    instance, kernwin = backend
    second = MagicMock()

    def first(result):
        instance.run_request("second", lambda: "two", second)

    instance.run_request("first", lambda: "one", first)
    _finish_work(instance)
    kernwin.timers.fire()
    # the second worker may answer before the first delivery pass ends; then it is delivered in it
    if not second.called:
        assert kernwin.timers.callback is not None
        _finish_work(instance)
        kernwin.timers.fire()

    second.assert_called_once_with("two")
    assert kernwin.timers.callback is None


def test_results_wait_while_on_done_shows_a_dialog(backend):
    instance, kernwin = backend
    order = []

    def first(result):
        # a modal dialog's event loop fires the timer again
        kernwin.timers.callback()
        order.append("first")

    instance.run_request("first", lambda: 1, first)
    _finish_work(instance)
    instance.run_request("nested", lambda: 2, lambda result: order.append("nested"))
    _finish_work(instance)
    kernwin.timers.fire()

    assert order == ["first", "nested"]


def test_close_drops_pending_results_and_stops_the_timer(backend):
    instance, kernwin = backend
    on_done = MagicMock()

    instance.run_request("Query", lambda: "late", on_done)
    executor = instance._executor
    executor.shutdown(wait=True)
    instance.close()

    assert kernwin.timers.unregistered
    on_done.assert_not_called()
    instance.run_request("Query", lambda: "after", on_done)
    assert instance._executor is None, "a closed backend starts no requests"


def test_an_on_done_that_raises_does_not_stop_later_results(backend):
    instance, kernwin = backend
    later = MagicMock()

    def broken(result):
        raise ValueError("render failed")

    instance.run_request("broken", lambda: 1, broken)
    instance.run_request("later", lambda: 2, later)
    _finish_work(instance)
    kernwin.timers.fire()

    later.assert_called_once_with(2)
