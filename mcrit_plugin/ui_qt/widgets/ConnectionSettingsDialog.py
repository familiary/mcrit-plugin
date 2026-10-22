from urllib.parse import urlparse

import mcrit_plugin.ui_qt.QtShim as QtShim

QDialog = QtShim.get_QDialog()


class ConnectionSettingsDialog(QDialog):
    """Edit the four connection settings in place; values() holds them once accepted."""

    def __init__(self, parent, config):
        self.cc = parent.cc
        self.cc.QDialog.__init__(self, parent)
        self.setWindowTitle("MCRIT Settings")
        self.setMinimumWidth(460)
        intro = self.cc.QLabel("Where should the plugin find your MCRIT server?")
        self.edit_server = self.cc.QLineEdit(config.MCRIT_SERVER or "")
        self.edit_server.setPlaceholderText("https://mcrit.example.com/api")
        self.edit_token = self.cc.QLineEdit(config.MCRITWEB_API_TOKEN or "")
        self.edit_token.setEchoMode(self.cc.QLineEdit.Password)
        self.edit_token.setPlaceholderText("only needed for MCRITweb")
        self.cb_show_token = self.cc.QCheckBox("Show")
        self.cb_show_token.toggled.connect(self._onShowTokenToggled)
        self.edit_username = self.cc.QLineEdit(config.MCRITWEB_USERNAME or "")
        self.edit_username.setPlaceholderText("optional, the token implies it")
        self.spin_timeout = self.cc.QSpinBox()
        # a QSpinBox holds a 32-bit int
        timeout = min(config.MCRIT_REQUEST_TIMEOUT, 2**31 - 1)
        self.spin_timeout.setRange(0, max(3600, timeout))
        self.spin_timeout.setSuffix(" s")
        self.spin_timeout.setSpecialValueText("no limit")
        self.spin_timeout.setValue(timeout)
        token_row = self.cc.QHBoxLayout()
        token_row.addWidget(self.edit_token)
        token_row.addWidget(self.cb_show_token)
        grid = self.cc.QGridLayout()
        grid.addWidget(self.cc.QLabel("Server URL:"), 0, 0)
        grid.addWidget(self.edit_server, 0, 1)
        grid.addWidget(self.cc.QLabel("API token:"), 1, 0)
        grid.addLayout(token_row, 1, 1)
        grid.addWidget(self.cc.QLabel("Username:"), 2, 0)
        grid.addWidget(self.edit_username, 2, 1)
        grid.addWidget(self.cc.QLabel("Timeout:"), 3, 0)
        grid.addWidget(self.spin_timeout, 3, 1)
        self.label_error = self.cc.QLabel("")
        self.label_error.setStyleSheet("color: #d9534f;")
        self.label_error.setVisible(False)
        layout = self.cc.QVBoxLayout()
        layout.addWidget(intro)
        layout.addLayout(grid)
        layout.addWidget(self.label_error)
        notes = []
        fields = {
            "mcrit_server": self.edit_server,
            "mcritweb_api_token": self.edit_token,
            "mcritweb_username": self.edit_username,
            "mcrit_request_timeout": self.spin_timeout,
        }
        self._forced = sorted(key for key in fields if key in config.overriddenSettings())
        for key in self._forced:
            fields[key].setEnabled(False)
        if self._forced:
            notes.append("Greyed out: set by config_override.json, so only that file changes them.")
        if self.cc.backend.settings_hint:
            notes.append(self.cc.backend.settings_hint)
        for note in notes:
            label = self.cc.QLabel(note)
            label.setWordWrap(True)
            label.setTextInteractionFlags(self.cc.QtCore.Qt.TextSelectableByMouse)
            layout.addWidget(label)
        buttons = self.cc.QHBoxLayout()
        self.save_button = self.cc.QPushButton("Save and connect")
        self.save_button.setDefault(True)
        self.cancel_button = self.cc.QPushButton("Cancel")
        self.save_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        buttons.addStretch(1)
        buttons.addWidget(self.save_button)
        buttons.addWidget(self.cancel_button)
        layout.addLayout(buttons)
        self.setLayout(layout)
        self._initial_values = self.values()

    def _onShowTokenToggled(self, checked):
        self.edit_token.setEchoMode(
            self.cc.QLineEdit.Normal if checked else self.cc.QLineEdit.Password
        )

    def values(self):
        return {
            "mcrit_server": self.edit_server.text().strip(),
            "mcritweb_api_token": self.edit_token.text().strip(),
            "mcritweb_username": self.edit_username.text().strip(),
            "mcrit_request_timeout": self.spin_timeout.value(),
        }

    def changedValues(self):
        """The values the user changed, so untouched settings keep what the store has."""
        return {
            key: value for key, value in self.values().items() if value != self._initial_values[key]
        }

    def accept(self):
        if "mcrit_server" in self._forced:
            self.cc.QDialog.accept(self)
            return
        try:
            url = urlparse(self.edit_server.text().strip())
            # urllib raises here for a port that is not a number from 0 to 65535
            _port = url.port
            valid = url.scheme.lower() in ("http", "https") and bool(url.hostname)
        except ValueError:
            valid = False
        if not valid:
            self.label_error.setText(
                "The server URL has to look like https://mcrit.example.com/api"
            )
            self.label_error.setVisible(True)
            self.edit_server.setFocus()
            return
        self.cc.QDialog.accept(self)
