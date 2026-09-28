"""Tests for McritConfig in mcrit_plugin/core/config.py.

The wrapper coerces strings coming from IDA's settings store into the right
Python types and substitutes a sane default if coercion fails. These tests
pin those rules so a future refactor can't silently regress them.
"""

import importlib
import logging
import sys
from unittest.mock import patch

import pytest


def _reload_config():
    """Reload the config module to reset module-level state.

    Returns:
        The reloaded config module.
    """
    sys.modules.pop("mcrit_plugin.core.config", None)
    return importlib.import_module("mcrit_plugin.core.config")


@pytest.fixture
def fresh_config():
    """Fixture that provides a freshly loaded config module for testing."""
    return _reload_config()


def test_mcrit_request_timeout_default(fresh_config):
    settings = fresh_config.McritConfig("0.0.0")
    assert settings.MCRIT_REQUEST_TIMEOUT == 10


@pytest.mark.parametrize(
    "raw_value, expected",
    [
        ("15", 15),
        (20, 20),
        ("0", 0),
    ],
)
def test_mcrit_request_timeout_valid_coercions(fresh_config, raw_value, expected):
    settings = fresh_config.McritConfig("0.0.0")
    with patch.object(settings, "_get", return_value=raw_value):
        assert settings.MCRIT_REQUEST_TIMEOUT == expected


@pytest.mark.parametrize(
    "raw_value",
    [
        "not-a-number",
        None,
        object(),
    ],
)
def test_mcrit_request_timeout_invalid_falls_back_to_default(fresh_config, raw_value):
    settings = fresh_config.McritConfig("0.0.0")
    with patch.object(settings, "_get", return_value=raw_value):
        assert settings.MCRIT_REQUEST_TIMEOUT == 10


def test_sample_group_only_default(fresh_config):
    settings = fresh_config.McritConfig("0.0.0")
    assert settings.SAMPLE_GROUP_ONLY is False


@pytest.mark.parametrize(
    "raw_value, expected",
    [
        (False, False),
        (True, True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("true", True),
        ("yes", True),
        (1, True),
    ],
)
def test_sample_group_only_coerces_setting_value(fresh_config, raw_value, expected):
    settings = fresh_config.McritConfig("0.0.0")
    with patch.object(settings, "_get", return_value=raw_value):
        assert settings.SAMPLE_GROUP_ONLY is expected


BOOL_PROPERTIES = [
    "SAMPLE_GROUP_ONLY",
    "AUTO_ANALYZE_SMDA_ON_STARTUP",
    "USE_SMDA_FOR_ANALYSIS",
    "SUBMIT_FUNCTION_NAMES_ON_CLOSE",
    "BLOCKS_FILTER_LIBRARY_FUNCTIONS",
    "BLOCKS_LIVE_QUERY",
    "FUNCTION_FILTER_LIBRARY_FUNCTIONS",
    "FUNCTION_LIVE_QUERY",
    "OVERVIEW_FETCH_LABELS_AUTOMATICALLY",
    "OVERVIEW_FILTER_TO_LABELS",
    "OVERVIEW_FILTER_TO_CONFLICTS",
]


@pytest.mark.parametrize("property_name", BOOL_PROPERTIES)
@pytest.mark.parametrize(
    "raw_value, expected",
    [
        (False, False),
        (True, True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("", False),
        ("true", True),
        ("yes", True),
        (1, True),
    ],
)
def test_bool_properties_coerce_setting_value(fresh_config, property_name, raw_value, expected):
    settings = fresh_config.McritConfig("0.0.0")
    with patch.object(settings, "_get", return_value=raw_value):
        assert getattr(settings, property_name) is expected


def test_blocks_min_size_default(fresh_config):
    settings = fresh_config.McritConfig("0.0.0")
    assert settings.BLOCKS_MIN_SIZE == 4


def test_blocks_min_size_string_coerced(fresh_config):
    settings = fresh_config.McritConfig("0.0.0")
    with patch.object(settings, "_get", return_value="8"):
        assert settings.BLOCKS_MIN_SIZE == 8


def test_blocks_min_size_invalid_falls_back(fresh_config):
    settings = fresh_config.McritConfig("0.0.0")
    with patch.object(settings, "_get", return_value="bogus"):
        assert settings.BLOCKS_MIN_SIZE == 4


def test_function_min_score_default(fresh_config):
    settings = fresh_config.McritConfig("0.0.0")
    assert settings.FUNCTION_MIN_SCORE == 50


def test_overview_min_score_default(fresh_config):
    settings = fresh_config.McritConfig("0.0.0")
    assert settings.OVERVIEW_MIN_SCORE == 50


def test_version_matches_ida_plugin_json():
    """ida-plugin.json and config.VERSION must agree on the plugin version."""
    import json
    import os

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
    with open(os.path.join(project_root, "mcrit_plugin", "ida", "ida-plugin.json"), "r") as fh:
        manifest = json.load(fh)
    ida_config = importlib.import_module("mcrit_plugin.ida.config")
    assert manifest["plugin"]["version"] == ida_config.VERSION


def test_manifest_declares_sample_group_only_setting():
    import json
    import os

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
    with open(os.path.join(project_root, "mcrit_plugin", "ida", "ida-plugin.json"), "r") as fh:
        manifest = json.load(fh)

    settings = {setting["key"]: setting for setting in manifest["plugin"]["settings"]}
    assert settings["sample_group_only"]["type"] == "boolean"
    assert settings["sample_group_only"]["default"] is False


def test_override_template_declares_sample_group_only_default():
    import json
    import os

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
    with open(os.path.join(project_root, "docs", "config_override.json.template"), "r") as fh:
        override_template = json.load(fh)

    assert override_template["sample_group_only"] is False


def test_plugin_loggers_do_not_propagate_to_existing_root_handler(fresh_config):
    root = logging.getLogger()
    root_handler = logging.StreamHandler()
    root_handler.setFormatter(logging.Formatter("[Diaphora: %(message)s]"))
    root.addHandler(root_handler)
    try:
        config = _reload_config()
        smda_logger = logging.getLogger("smda.ida.IdaExporter")
        minimcrit_logger = logging.getLogger("mcrit_plugin.core.minimcrit.client.McritClient")

        assert logging.getLogger("smda").propagate is False
        assert logging.getLogger("mcrit_plugin.core.minimcrit").propagate is False
        assert any(
            getattr(handler, "_mcrit_plugin_handler", False)
            for handler in logging.getLogger("smda").handlers
        )
        assert any(
            getattr(handler, "_mcrit_plugin_handler", False)
            for handler in logging.getLogger("mcrit_plugin.core.minimcrit").handlers
        )
        assert smda_logger.getEffectiveLevel() == config.LOG_LEVEL
        assert minimcrit_logger.getEffectiveLevel() == config.LOG_LEVEL
    finally:
        root.removeHandler(root_handler)
