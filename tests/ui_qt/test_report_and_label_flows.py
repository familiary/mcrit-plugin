"""A failed re-export leaves no report to keep metadata on, and label imports count only the names
the disassembler accepted."""

import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.core.McritTableColumn as McritTableColumn  # noqa: E402
from mcrit_plugin.ui_qt.widgets.FunctionOverviewWidget import FunctionOverviewWidget  # noqa: E402
from mcrit_plugin.ui_qt.widgets.MainWidget import MainWidget  # noqa: E402


def test_a_failed_export_is_reported_instead_of_raising():
    widget = SimpleNamespace(
        parent=SimpleNamespace(
            local_smda_report=SimpleNamespace(family="fam", version="1", is_library=False),
            local_widget=MagicMock(),
        )
    )
    for name in ("_keepMetadata", "_exportReport"):
        setattr(widget, name, types.MethodType(getattr(MainWidget, name), widget))

    widget._exportReport(None)

    assert widget.parent.local_smda_report is None
    assert "not converted" in widget.parent.local_widget.updateActivityInfo.call_args.args[0]


def test_a_refused_name_counts_as_skipped():
    rows = [
        SimpleNamespace(offset=0x1000, selected_text="0.9|good_name"),
        SimpleNamespace(offset=0x2000, selected_text="0.9|bad name"),
    ]
    backend = SimpleNamespace(
        mutation=lambda _title: MagicMock(),
        has_default_function_name=lambda _offset: True,
        set_function_name=lambda _offset, name: " " not in name,
    )
    widget = SimpleNamespace(
        cc=SimpleNamespace(backend=backend),
        parent=SimpleNamespace(
            config=SimpleNamespace(OVERVIEW_TABLE_COLUMNS=[McritTableColumn.SCORE_AND_LABEL]),
            local_widget=MagicMock(),
        ),
        table_local_functions=SimpleNamespace(table_model=SimpleNamespace(rows=rows)),
        update=MagicMock(),
    )

    FunctionOverviewWidget.importSelectedLabels(widget)

    message = widget.parent.local_widget.updateActivityInfo.call_args_list[-1].args[0]
    assert "Imported 1 function names (skipped: 1)" in message
