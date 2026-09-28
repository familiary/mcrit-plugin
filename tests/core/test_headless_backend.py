"""HeadlessBackend's default-name rule matches the one the IDA and Binary Ninja backends apply."""

from types import SimpleNamespace

import pytest

from mcrit_plugin.headless.HeadlessBackend import HeadlessBackend


@pytest.fixture
def backend():
    functions = {0x10: "", 0x20: "sub_20", 0x30: "parse_config"}
    instance = HeadlessBackend.__new__(HeadlessBackend)
    instance._names = {}
    disassembly = SimpleNamespace(
        getFunction=lambda address: (
            SimpleNamespace(function_name=functions[address]) if address in functions else None
        )
    )
    instance._disassembly = lambda: disassembly
    return instance


@pytest.mark.parametrize(
    "address, expected", [(0x10, True), (0x20, True), (0x30, False), (0x40, False)]
)
def test_unnamed_and_sub_names_are_default(backend, address, expected):
    assert backend.has_default_function_name(address) is expected


def test_a_name_set_here_is_not_default(backend):
    backend.set_function_name(0x10, "imported_label")

    assert backend.has_default_function_name(0x10) is False
