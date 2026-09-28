"""The Binary Ninja API token moves into the system keychain and is cleared from it again.

binaryninja is stubbed: Settings is a dict and the keychain a fake SecretsProvider.
"""

import importlib
import sys
import types

import pytest


class _Settings:
    store = {}

    def get_string(self, key):
        return self.store.get(key, "")

    def reset(self, key):
        self.store.pop(key, None)

    def contains(self, key):
        return True


class _Keychain:
    def __init__(self):
        self.data = {}

    def store_data(self, key, value):
        self.data[key] = value
        return True

    def has_data(self, key):
        return key in self.data

    def get_data(self, key):
        return self.data[key]

    def delete_data(self, key):
        del self.data[key]


@pytest.fixture
def binja_config(monkeypatch):
    keychain = _Keychain()
    providers = {"SystemSecretsProvider": keychain}
    _Settings.store = {}
    monkeypatch.setitem(
        sys.modules,
        "binaryninja",
        types.SimpleNamespace(
            SecretsProvider=types.SimpleNamespace(get=providers.get),
            Settings=_Settings,
            log_error=lambda message: None,
        ),
    )
    monkeypatch.delitem(sys.modules, "mcrit_plugin.binja.config", raising=False)
    module = importlib.import_module("mcrit_plugin.binja.config")
    return module, keychain


def test_a_typed_token_moves_into_the_keychain(binja_config):
    module, keychain = binja_config
    _Settings.store["mcrit.mcritweb_api_token"] = "secret"

    assert module._get_setting("mcritweb_api_token") == "secret"
    assert keychain.data == {"mcrit.mcritweb_api_token": "secret"}
    assert "mcrit.mcritweb_api_token" not in _Settings.store
    assert module._get_setting("mcritweb_api_token") == "secret"


def test_clearing_removes_the_token_from_keychain_and_settings(binja_config):
    module, keychain = binja_config
    keychain.data["mcrit.mcritweb_api_token"] = "secret"
    _Settings.store["mcrit.mcritweb_api_token"] = "typed"

    module.clear_stored_secrets()

    assert keychain.data == {}
    assert "mcrit.mcritweb_api_token" not in _Settings.store


def test_without_a_keychain_the_token_stays_in_settings(binja_config, monkeypatch):
    module, keychain = binja_config
    monkeypatch.setattr(module, "KEYCHAIN_PROVIDER", "NoSuchProvider")
    _Settings.store["mcrit.mcritweb_api_token"] = "secret"

    assert module._get_setting("mcritweb_api_token") == "secret"
    assert keychain.data == {}
    assert _Settings.store["mcrit.mcritweb_api_token"] == "secret"
