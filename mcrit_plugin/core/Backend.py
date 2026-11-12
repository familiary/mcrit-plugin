import re
import threading
import time
import traceback
from abc import ABC, abstractmethod
from contextlib import contextmanager

# while background jobs keep failing, e.g. one live query per cursor move, one dialog per this
# many seconds; the other failures go to the console
FAILURE_WARNING_INTERVAL = 30


def run_until_cancelled(work, cancelled, interval=0.1):
    """Run work() on a thread of its own and wait for it; False once cancelled() says to stop
    waiting. A cancelled work() is left to finish or fail on its own, as a request cannot be
    stopped."""
    done = threading.Event()
    abandoned = threading.Event()

    def run():
        try:
            work()
        except Exception:
            # what it reports to is gone once the caller moved on
            if not abandoned.is_set():
                traceback.print_exc()
        finally:
            done.set()

    threading.Thread(target=run, name="mcrit-blocking", daemon=True).start()
    while not done.wait(interval):
        if cancelled():
            abandoned.set()
            return False
    return True


class Backend(ABC):
    """Disassembler operations used by the shared MCRIT core and widgets.

    Addresses are plain ints; "no address" is None, never a tool-specific BADADDR.
    """

    name = ""
    # set when the plugin's form or sidebar closes; background work stops early once it is
    closed = False
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
    def get_function_offsets(self):
        """Start addresses of the functions export_smda_report would export, without exporting."""

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
        """Rename the function starting at address; True when the disassembler took the name."""

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

    def run_request(self, title, work, on_done):
        """Run work(), requests to the MCRIT server, off the UI thread where the disassembler
        allows it, then on_done(result) on the UI thread; title names it where progress is shown.

        work must not touch Qt widgets directly. The default runs synchronously.
        """
        on_done(work())

    def run_blocking(self, title, work):
        """Run work(), a request the caller has to wait for such as the upload before a file
        closes, behind the disassembler's own wait dialog with a Cancel button; False when the
        user cancelled the wait. Called on the UI thread; work runs off it and must not use the
        disassembler's API. The default runs synchronously.
        """
        work()
        return True

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

    def show_failure(self, message):
        """Warning for a failed background job: modal, unless the same kind of job, the message
        without its addresses and numbers, got one within FAILURE_WARNING_INTERVAL seconds.
        Another job's failure, such as an export's, always gets its dialog."""
        if not hasattr(self, "_failure_warnings"):
            self._failure_warnings = {}
        kind = re.sub(r"0x[0-9a-fA-F]+|\d+", "#", message)
        now = time.monotonic()
        if now - self._failure_warnings.get(kind, float("-inf")) < FAILURE_WARNING_INTERVAL:
            print("[MCRIT] %s" % message)
            return
        self._failure_warnings[kind] = now
        self.show_warning(message)

    # shown under the plugin's own connection form, e.g. where the remaining settings live
    settings_hint = ""
    # what rebuilds the session, so a new server can take over
    reopen_hint = "reopen MCRIT"
    # where the user changes the server, named in the hint after a failed connection check
    settings_location = "the Settings button"

    def open_settings(self, config):
        """Open the disassembler's own settings UI on this plugin and return its QWidget, or True
        when it opened but cannot be watched for closing.

        None means there is none, and the plugin shows its own connection form instead.
        """
        return None

    def save_settings(self, values):
        """Store the connection form's values (setting key -> value) in the settings store."""
        raise NotImplementedError

    def theme_color(self, role, default):
        """RGB tuple for a ScoreColorProvider.ThemeRole; None keeps the widget's own color and is
        valid only for TEXT_ON_TINT.

        Backends that follow a user-selectable theme override this; the default keeps `default`.
        """
        return default

    def show_local_match_coloring(self, smda_function, coloring):
        """Tint the matched blocks of the local function in the disassembler's own views;
        coloring maps block offset -> 0xRRGGBB. Backends without such a view keep this no-op."""

    def clear_local_match_coloring(self):
        """Remove the tint set by show_local_match_coloring."""

    @abstractmethod
    def show_function_graph(self, parent, sample_entry, function_entry, smda_function, coloring):
        """Show the CFG of a remote SMDA function; coloring maps block offset -> 0xRRGGBB."""
