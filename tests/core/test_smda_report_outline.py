"""Regression tests for the per-query SMDA report outline.

SMDA 4.8 memoises `SmdaReport.getFunctions()`, so reusing one outline object and only
swapping its `xcfg` makes every query after the first look at the first function again.
"""

import sys
import types

import pytest

from mcrit_plugin.ui_qt.McritSession import McritSession


class _CachingSmdaReport:
    """SmdaReport stand-in with SMDA >= 4.8 `getFunctions()` caching semantics."""

    def __init__(self, xcfg=None, sha256="a" * 64):
        self.xcfg = xcfg or {}
        self.sha256 = sha256
        self._sorted_functions = None

    @classmethod
    def fromDict(cls, data):
        return cls(data.get("xcfg"), data.get("sha256"))

    def toDict(self):
        return {"xcfg": dict(self.xcfg), "sha256": self.sha256}

    def getFunctions(self):
        if self._sorted_functions is None:
            self._sorted_functions = (
                [function for _, function in sorted(self.xcfg.items())] if self.xcfg else []
            )
        yield from self._sorted_functions


@pytest.fixture
def outline_getter(monkeypatch):
    """The bare `getLocalSmdaReportOutline` method, resolving SmdaReport to a caching stand-in."""
    monkeypatch.setitem(
        sys.modules,
        "smda.common.SmdaReport",
        types.SimpleNamespace(SmdaReport=_CachingSmdaReport),
    )
    return McritSession.getLocalSmdaReportOutline


def _make_session(local_report):
    return types.SimpleNamespace(
        local_smda_report=local_report,
        local_smda_report_outline=None,
        _outline_source=None,
    )


def test_outline_is_a_fresh_report_per_query(outline_getter):
    local_report = _CachingSmdaReport({0x1000: "func_a", 0x2000: "func_b"})
    session = _make_session(local_report)

    first = outline_getter(session)
    first.xcfg = {0x1000: "func_a"}
    assert list(first.getFunctions()) == ["func_a"]

    second = outline_getter(session)
    second.xcfg = {0x2000: "func_b"}
    assert list(second.getFunctions()) == ["func_b"]

    assert first is not second


def test_outline_carries_no_functions(outline_getter):
    session = _make_session(_CachingSmdaReport({0x1000: "func_a", 0x2000: "func_b"}))

    outline = outline_getter(session)

    assert outline.xcfg == {}
    assert list(outline.getFunctions()) == []


def test_outline_follows_a_replaced_local_report(outline_getter):
    """Uploading on close swaps local_smda_report, and the outline must not stay on the old one."""
    session = _make_session(_CachingSmdaReport({0x1000: "func_a"}, sha256="b" * 64))
    outline_getter(session)

    session.local_smda_report = _CachingSmdaReport({0x3000: "func_c"}, sha256="c" * 64)
    refreshed = outline_getter(session)
    refreshed.xcfg = {0x3000: "func_c"}

    assert refreshed.sha256 == "c" * 64
    assert list(refreshed.getFunctions()) == ["func_c"]


def test_outline_is_none_without_a_local_report(outline_getter):
    assert outline_getter(_make_session(None)) is None
