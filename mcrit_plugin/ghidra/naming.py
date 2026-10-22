"""Ghidra's function and import names, in the forms the rest of the plugin expects."""

import re

# Ghidra's auto-generated function names: FUN_00401000, thunk_FUN_00401000, and SUB_ for some loaders
DEFAULT_NAME = re.compile(r"(thunk_)?(FUN|SUB)_[0-9a-fA-F]+$")
# the library Ghidra files imports under when the binary does not name one (ELF)
UNKNOWN_LIBRARY = "<EXTERNAL>"


def is_default_name(name):
    return DEFAULT_NAME.match(name or "") is not None


def api_name(library, name):
    """SMDA's "dll!api" form: library names in lower case, none for an unknown library."""
    if library and library != UNKNOWN_LIBRARY:
        return f"{library.lower()}!{name}"
    return name
