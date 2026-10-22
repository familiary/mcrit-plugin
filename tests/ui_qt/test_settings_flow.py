"""The Settings button opens the disassembler's own settings, or the plugin's connection form, and
a changed connection is picked up without reopening the plugin."""

import os
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.QtShim as QtShim  # noqa: E402
from mcrit_plugin.ui_qt.ClassCollection import ClassCollection  # noqa: E402
from mcrit_plugin.ui_qt.widgets.ConnectionSettingsDialog import (  # noqa: E402
    ConnectionSettingsDialog,
)
from mcrit_plugin.ui_qt.widgets.MainWidget import MainWidget  # noqa: E402

_ICON_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "icons") + os.sep


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def _config(**overrides):
    values = dict(
        MCRIT_SERVER="http://127.0.0.1:8000/",
        MCRITWEB_API_TOKEN="",
        MCRITWEB_USERNAME="",
        MCRIT_REQUEST_TIMEOUT=10,
    )
    values.update(overrides)
    config = SimpleNamespace(**values)
    config.overriddenSettings = lambda: set()
    return config


def _dialog(app, config, hint=""):
    host = QtWidgets.QWidget()
    host.cc = ClassCollection(QtShim, SimpleNamespace(settings_hint=hint))
    return ConnectionSettingsDialog(host, config), host


def test_the_form_starts_from_the_current_settings(app):
    config = _config(MCRITWEB_API_TOKEN="secret", MCRIT_REQUEST_TIMEOUT=30)
    dialog, _host = _dialog(app, config)

    assert dialog.values() == {
        "mcrit_server": "http://127.0.0.1:8000/",
        "mcritweb_api_token": "secret",
        "mcritweb_username": "",
        "mcrit_request_timeout": 30,
    }
    assert dialog.edit_token.echoMode() == QtWidgets.QLineEdit.Password
    dialog.cb_show_token.setChecked(True)
    assert dialog.edit_token.echoMode() == QtWidgets.QLineEdit.Normal


@pytest.mark.parametrize(
    "server, accepted",
    [
        ("mcrit.example.com", False),
        ("http://", False),
        ("http://[::1", False),
        ("http://:8000", False),
        ("http://mcrit:abc/", False),
        ("http://mcrit:99999/", False),
        ("http://[::1]:8000/", True),
        ("HTTPS://mcrit.example.com/api", True),
        ("  https://mcrit.example.com/api ", True),
    ],
)
def test_the_form_accepts_only_an_http_url_with_a_host(app, server, accepted):
    dialog, _host = _dialog(app, _config())
    dialog.edit_server.setText(server)

    dialog.accept()

    assert (dialog.result() == QtWidgets.QDialog.Accepted) == accepted
    assert dialog.label_error.isHidden() == accepted


def test_only_the_changed_fields_are_saved(app):
    dialog, _host = _dialog(app, _config(MCRITWEB_API_TOKEN="secret"))
    assert dialog.changedValues() == {}

    dialog.edit_server.setText("https://mcrit.example.com/")

    assert dialog.changedValues() == {"mcrit_server": "https://mcrit.example.com/"}


def test_fields_forced_by_config_override_are_greyed_out(app):
    config = _config()
    config.overriddenSettings = lambda: {"mcrit_server", "blocks_min_size"}
    dialog, _host = _dialog(app, config, hint="other settings live elsewhere")

    texts = [label.text() for label in dialog.findChildren(QtWidgets.QLabel)]

    assert not dialog.edit_server.isEnabled()
    assert dialog.edit_token.isEnabled()
    assert any("config_override.json" in text for text in texts)
    assert "other settings live elsewhere" in texts


def _main_widget(opened, waiting_server=None):
    backend = SimpleNamespace(
        open_settings=MagicMock(return_value=opened),
        save_settings=MagicMock(),
        show_warning=MagicMock(),
        reopen_hint="reopen MCRIT",
    )
    interface = SimpleNamespace(
        reloadSettings=MagicMock(return_value=waiting_server),
        server="http://old:8000/",
    )
    widget = SimpleNamespace(
        cc=SimpleNamespace(backend=backend, QtCore=QtShim.get_QtCore()),
        parent=SimpleNamespace(
            config=_config(), mcrit_interface=interface, local_widget=MagicMock()
        ),
        _watchedSettingsWidget=None,
        _reportedWaitingServer=None,
    )
    for name in ("_onSettingsButtonClicked", "_onSettingsClosed", "_reportWaitingServer"):
        setattr(widget, name, types.MethodType(getattr(MainWidget, name), widget))
    return widget, backend, interface


@pytest.mark.parametrize("accepted", [True, False])
def test_without_a_settings_ui_the_form_saves_and_reconnects_only_when_accepted(accepted):
    widget, backend, interface = _main_widget(opened=None)
    values = {"mcrit_server": "https://mcrit.example.com/"}
    widget.ConnectionSettingsDialog = lambda parent, config: SimpleNamespace(
        exec_=lambda: accepted, changedValues=lambda: values
    )

    widget._onSettingsButtonClicked()

    if accepted:
        backend.save_settings.assert_called_once_with(values)
        interface.reloadSettings.assert_called_once_with(recheck=True)
    else:
        backend.save_settings.assert_not_called()
        interface.reloadSettings.assert_not_called()


def test_closing_the_opened_settings_reloads_them_once(app):
    settings_ui = QtWidgets.QWidget()
    widget, backend, interface = _main_widget(opened=settings_ui)

    widget._onSettingsButtonClicked()
    widget._onSettingsButtonClicked()
    settings_ui.deleteLater()
    app.sendPostedEvents(None, 52)  # QEvent.DeferredDelete
    app.processEvents()

    interface.reloadSettings.assert_called_once_with()
    assert widget._watchedSettingsWidget is None
    backend.show_warning.assert_not_called()


def test_a_server_that_waits_for_a_reopen_is_reported_once_after_closing_settings(app):
    widget, backend, interface = _main_widget(opened=None, waiting_server="https://new/")

    widget._onSettingsClosed()
    backend.show_warning.assert_not_called()
    app.processEvents()
    widget._onSettingsClosed()
    app.processEvents()
    assert backend.show_warning.call_count == 1

    # switched back, then to the new server again: that is worth another warning
    interface.reloadSettings.return_value = None
    widget._onSettingsClosed()
    app.processEvents()
    interface.reloadSettings.return_value = "https://new/"
    widget._onSettingsClosed()
    app.processEvents()
    assert backend.show_warning.call_count == 2


def test_a_server_that_waits_for_a_reopen_is_reported_after_the_form(app):
    widget, backend, _interface = _main_widget(opened=None, waiting_server="https://new/")
    widget.ConnectionSettingsDialog = lambda parent, config: SimpleNamespace(
        exec_=lambda: True, changedValues=lambda: {"mcrit_server": "https://new/"}
    )

    widget._onSettingsButtonClicked()

    message = backend.show_warning.call_args.args[0]
    assert "keeps using http://old:8000/" in message
    assert "reopen MCRIT to switch to https://new/" in message


def test_a_failed_save_warns_and_keeps_the_connection(app):
    widget, backend, interface = _main_widget(opened=None)
    backend.save_settings.side_effect = RuntimeError("mcrit-ida is not installed")
    widget.ConnectionSettingsDialog = lambda parent, config: SimpleNamespace(
        exec_=lambda: True, changedValues=lambda: {"mcrit_server": "https://x/"}
    )

    widget._onSettingsButtonClicked()

    assert "mcrit-ida is not installed" in backend.show_warning.call_args.args[0]
    interface.reloadSettings.assert_not_called()


def test_settings_opened_without_a_widget_to_watch_say_how_to_apply_them():
    widget, backend, interface = _main_widget(opened=True)
    widget.ConnectionSettingsDialog = MagicMock()

    widget._onSettingsButtonClicked()

    widget.ConnectionSettingsDialog.assert_not_called()
    assert widget._watchedSettingsWidget is None
    message = widget.parent.local_widget.updateActivityInfo.call_args.args[0]
    assert "reopen MCRIT after changing the connection" in message


def test_toolbar_icons_take_the_theme_text_color_and_keep_their_shape(app):
    host = QtWidgets.QWidget()
    palette = host.palette()
    palette.setColor(QtShim.get_QPalette().WindowText, QtShim.get_QtGui().QColor(230, 230, 230))
    host.setPalette(palette)
    host.cc = ClassCollection(QtShim, None)
    host.parent = SimpleNamespace(config=SimpleNamespace(ICON_FILE_PATH=_ICON_PATH))
    host._themedIcon = types.MethodType(MainWidget._themedIcon, host)

    source = QtShim.get_QtGui().QImage(_ICON_PATH + "settings.png")
    size, row = source.width(), source.height() * 7 // 24  # the upper slider line
    icon = MainWidget._toolbarIcon(host, "settings.png")
    image = icon.pixmap(size, size).toImage()

    opaque_x = next(x for x in range(size) if source.pixelColor(x, row).alpha() == 255)
    assert image.pixelColor(opaque_x, row).red() == 230
    assert [image.pixelColor(x, row).alpha() for x in range(size)] == [
        source.pixelColor(x, row).alpha() for x in range(size)
    ]


def test_a_theme_change_tints_the_icons_again(app):
    methods = ("changeEvent", "_applyIconTint", "_toolbarIcon", "_themedIcon")
    host_class = type(
        "Host", (QtWidgets.QMainWindow,), {name: getattr(MainWidget, name) for name in methods}
    )
    host = host_class()
    host.cc = ClassCollection(QtShim, None)
    host.parent = SimpleNamespace(config=SimpleNamespace(ICON_FILE_PATH=_ICON_PATH))
    action = QtShim.get_QtGui().QAction("Settings", host)
    host._toolbarIconFiles = [(action, "settings.png")]
    host.tabbed_widgets = []
    host.tabs = QtWidgets.QTabWidget()
    source = QtShim.get_QtGui().QImage(_ICON_PATH + "settings.png")
    size = source.width()
    opaque = next(
        (x, y) for y in range(size) for x in range(size) if source.pixelColor(x, y).alpha() == 255
    )

    for gray in (30, 230):
        palette = host.palette()
        palette.setColor(
            QtShim.get_QPalette().WindowText, QtShim.get_QtGui().QColor(gray, gray, gray)
        )
        host.setPalette(palette)
        assert action.icon().pixmap(size, size).toImage().pixelColor(*opaque).red() == gray


def test_the_server_line_escapes_what_the_server_sends_and_offers_the_change_link(app):
    from mcrit_plugin.ui_qt.widgets.LocalInfoWidget import LocalInfoWidget

    session = SimpleNamespace(
        cc=ClassCollection(QtShim, SimpleNamespace(plugin_name="MCRIT4Test")),
        config=SimpleNamespace(ICON_FILE_PATH=_ICON_PATH, VERSION="0", MCRIT_SERVER="http://s/"),
        main_widget=MagicMock(),
    )
    widget = LocalInfoWidget(session)
    assert "checking..." in widget.label_mcrit_server_info.text()

    widget._setServerInfo(("http://s/", "<b>1.0</b>", None))
    widget.label_mcrit_server_info.linkActivated.emit("settings")

    assert "&lt;b&gt;1.0&lt;/b&gt;" in widget.label_mcrit_server_info.text()
    session.main_widget._onSettingsButtonClicked.assert_called_once_with()
