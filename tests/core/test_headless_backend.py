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
        ),
        getFunctions=lambda: [SimpleNamespace(offset=address) for address in functions],
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


def test_requests_run_synchronously_by_default(backend):
    results = []

    backend.run_request("request", lambda: "answer", results.append)

    assert results == ["answer"]


def test_function_offsets_are_those_of_the_disassembly(backend):
    assert backend.get_function_offsets() == {0x10, 0x20, 0x30}
