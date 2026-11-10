"""Swing helpers for the Ghidra frontend: threading, background tasks, theme colors and the small
JPype adapters the widgets use for listeners.

JPype implements Java interfaces with @JImplements but cannot extend Java classes, so every
listener, renderer and model here is an interface implementation.
"""

import traceback

from jpype import JImplements, JOverride


@JImplements("java.lang.Runnable", deferred=True)
class PyRunnable:
    def __init__(self, func):
        self._func = func

    @JOverride
    def run(self):
        try:
            self._func()
        except Exception:
            traceback.print_exc()


@JImplements("ghidra.util.task.MonitoredRunnable", deferred=True)
class PyMonitoredRunnable:
    def __init__(self, func):
        self._func = func

    @JOverride
    def monitoredRun(self, monitor):
        try:
            self._func(monitor)
        except Exception:
            traceback.print_exc()


@JImplements("java.awt.event.ActionListener", deferred=True)
class ActionListener:
    def __init__(self, func):
        self._func = func

    @JOverride
    def actionPerformed(self, event):
        try:
            self._func(event)
        except Exception:
            traceback.print_exc()


@JImplements("java.util.function.Consumer", deferred=True)
class Consumer:
    def __init__(self, func):
        self._func = func

    @JOverride
    def accept(self, value):
        try:
            self._func(value)
        except Exception:
            traceback.print_exc()


@JImplements("javax.swing.event.ChangeListener", deferred=True)
class ChangeListener:
    def __init__(self, func):
        self._func = func

    @JOverride
    def stateChanged(self, event):
        try:
            self._func(event)
        except Exception:
            traceback.print_exc()


@JImplements("java.beans.PropertyChangeListener", deferred=True)
class PropertyChangeListener:
    def __init__(self, func):
        self._func = func

    @JOverride
    def propertyChange(self, event):
        try:
            self._func(event)
        except Exception:
            traceback.print_exc()


@JImplements("javax.swing.event.DocumentListener", deferred=True)
class DocumentListener:
    def __init__(self, func):
        self._func = func

    def _call(self, event):
        try:
            self._func(event)
        except Exception:
            traceback.print_exc()

    @JOverride
    def insertUpdate(self, event):
        self._call(event)

    @JOverride
    def removeUpdate(self, event):
        self._call(event)

    @JOverride
    def changedUpdate(self, event):
        self._call(event)


@JImplements("java.awt.event.MouseListener", deferred=True)
class MouseListener:
    """Calls on_click(event) for every click; event.getClickCount() tells double clicks apart.
    on_press(event) runs for every press, before the popup check."""

    def __init__(self, on_click=None, on_popup=None, on_press=None):
        self._on_click = on_click
        self._on_popup = on_popup
        self._on_press = on_press

    def _popup(self, event):
        if self._on_popup is not None and event.isPopupTrigger():
            try:
                self._on_popup(event)
            except Exception:
                traceback.print_exc()

    @JOverride
    def mouseClicked(self, event):
        if self._on_click is not None:
            try:
                self._on_click(event)
            except Exception:
                traceback.print_exc()

    @JOverride
    def mousePressed(self, event):
        if self._on_press is not None:
            try:
                self._on_press(event)
            except Exception:
                traceback.print_exc()
        # popups trigger on press on Linux and macOS, on release on Windows
        self._popup(event)

    @JOverride
    def mouseReleased(self, event):
        self._popup(event)

    @JOverride
    def mouseEntered(self, event):
        pass

    @JOverride
    def mouseExited(self, event):
        pass


def is_swing_thread():
    from java.awt import EventQueue

    return bool(EventQueue.isDispatchThread())


def invoke_later(func):
    from javax.swing import SwingUtilities

    SwingUtilities.invokeLater(PyRunnable(func))


def invoke_and_wait(func):
    """Run func on the event dispatch thread and return its result, raising what it raised."""
    if is_swing_thread():
        return func()
    from javax.swing import SwingUtilities

    outcome = []

    def call():
        try:
            outcome.append((func(), None))
        except Exception as exc:
            outcome.append((None, exc))

    @JImplements("java.lang.Runnable", deferred=True)
    class _Call:
        @JOverride
        def run(self):
            call()

    SwingUtilities.invokeAndWait(_Call())
    if not outcome:
        return None
    result, error = outcome[0]
    if error is not None:
        raise error
    return result


def launch_background_task(title, func):
    """Run func(monitor) as a Ghidra task with a non-modal progress dialog; returns at once."""
    from ghidra.util.task import TaskBuilder

    (
        TaskBuilder.withRunnable(PyMonitoredRunnable(func))
        .setTitle(title)
        .setCanCancel(False)
        .setHasProgress(False)
        .launchNonModal()
    )


def _rgb(color):
    return (int(color.getRed()), int(color.getGreen()), int(color.getBlue()))


def is_dark_theme():
    try:
        from generic.theme import Gui

        return bool(Gui.isDarkTheme())
    except Exception:
        return False


def table_background():
    from javax.swing import UIManager

    color = UIManager.getColor("Table.background")
    return _rgb(color) if color is not None else (0xFF, 0xFF, 0xFF)


def selection_background():
    from javax.swing import UIManager

    color = UIManager.getColor("Table.selectionBackground")
    return _rgb(color) if color is not None else (0x00, 0xDD, 0xFF)
