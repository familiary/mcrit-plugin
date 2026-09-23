from abc import ABC, abstractmethod
from contextlib import contextmanager


class Backend(ABC):
    """Disassembler operations used by the shared MCRIT core and widgets.

    Addresses are plain ints; "no address" is None, never a tool-specific BADADDR.
    """

    name = ""
    # identifies the producing plugin in uploaded SMDA reports and the UI, e.g. "MCRIT4IDA"
    plugin_name = ""

    @abstractmethod
    def get_input_md5(self):
        """Hex MD5 of the input file, or None when no input is loaded."""

    @abstractmethod
    def get_input_sha256(self):
        """Hex SHA256 of the input file."""

    @abstractmethod
    def get_input_filename(self):
        """Base name of the input file."""

    @abstractmethod
    def get_input_size(self):
        """Size of the input file in bytes."""

    @abstractmethod
    def export_smda_report(self):
        """SmdaReport built from the disassembler's own analysis."""

    @abstractmethod
    def get_binary_info(self):
        """SMDA BinaryInfo (mapped bytes, architecture, base, bitness) for SMDA's own disassembly."""

    @abstractmethod
    def get_function_symbols(self):
        """Dict of function start address -> current function name."""

    @abstractmethod
    def get_cursor_address(self):
        """Address under the cursor in the active view, or None."""

    @abstractmethod
    def get_selection(self):
        """(start, end) of the active selection, end exclusive; (None, None) without one."""

    @abstractmethod
    def get_current_function(self, view=None):
        """Start address of the function under the cursor, or None.

        view is whatever the frontend's cursor hook hands over: IDA passes the widget the event
        came from, Binary Ninja the new offset. Widgets only forward it, never interpret it.
        """

    @abstractmethod
    def read_bytes(self, address, size):
        """Bytes of the analyzed image."""

    @abstractmethod
    def jump_to(self, address):
        """Navigate the active view to address."""

    @abstractmethod
    def get_function_name(self, address):
        """Name of the function starting at address, or None."""

    @abstractmethod
    def set_function_name(self, address, name):
        """Rename the function starting at address."""

    @abstractmethod
    def has_default_function_name(self, address):
        """True when the function still carries the disassembler's auto-generated name."""

    @contextmanager
    def mutation(self, title):
        """Group database changes, e.g. applying many labels, into one undoable step. Nested
        mutations join the enclosing one, so per-item helpers may open their own."""
        yield

    def run_background(self, title, work, on_done):
        """Run work() off the UI thread when the disassembler supports it, then on_done(result) on the UI thread.

        work must not touch Qt widgets directly. The default runs synchronously.
        """
        on_done(work())

    @abstractmethod
    def run_on_ui_thread(self, func):
        """Run func on the UI thread and wait for it."""

    @abstractmethod
    def ask_save_file(self, default_name, prompt):
        """Path chosen in a save-file dialog, or None."""

    @abstractmethod
    def ask_yes_no(self, prompt):
        """True when the user confirms."""

    @abstractmethod
    def show_warning(self, message):
        """Modal warning."""

    def theme_color(self, role, default):
        """RGB tuple for a ScoreColorProvider.ThemeRole, or None to keep the widget's own color.

        Backends that follow a user-selectable theme override this; the default keeps `default`.
        """
        return default

    @abstractmethod
    def show_function_graph(self, parent, sample_entry, function_entry, smda_function, coloring):
        """Show the CFG of a remote SMDA function; coloring maps block offset -> 0xRRGGBB."""
