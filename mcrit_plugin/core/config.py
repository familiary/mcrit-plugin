import json
import logging
import os
import sys

import mcrit_plugin.core.McritTableColumn as McritTableColumn

PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ICON_FILE_PATH = os.path.join(PLUGIN_ROOT, "icons") + os.sep
LOG_LEVEL = logging.INFO


def _configure_plugin_loggers():
    """Keep plugin-related logs from inheriting another plugin's root formatter."""
    formatter = logging.Formatter("%(asctime)-15s: %(name)-32s - %(levelname)s: %(message)s")
    for logger_name in ("mcrit_plugin.core.minimcrit", "smda"):
        logger = logging.getLogger(logger_name)
        logger.setLevel(LOG_LEVEL)
        logger.propagate = False
        if any(getattr(handler, "_mcrit_plugin_handler", False) for handler in logger.handlers):
            continue
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(LOG_LEVEL)
        handler.setFormatter(formatter)
        handler._mcrit_plugin_handler = True
        logger.addHandler(handler)


_configure_plugin_loggers()


class McritConfig:
    """Plugin settings with type coercion and defaults, read through a disassembler-specific getter."""

    ICON_FILE_PATH = ICON_FILE_PATH
    LOG_LEVEL = LOG_LEVEL

    BLOCK_SUMMARY_TABLE_COLUMNS = [
        McritTableColumn.OFFSET,
        McritTableColumn.PIC_BLOCK_HASH,
        McritTableColumn.SIZE,
        McritTableColumn.FAMILIES,
        McritTableColumn.SAMPLES,
        McritTableColumn.FUNCTIONS,
        McritTableColumn.IS_LIBRARY,
    ]
    BLOCK_MATCHES_TABLE_COLUMNS = [
        McritTableColumn.FAMILY_NAME,
        McritTableColumn.FAMILY_ID,
        McritTableColumn.SAMPLE_ID,
        McritTableColumn.FUNCTION_ID,
        McritTableColumn.OFFSET,
        # McritTableColumn.SHA256,
    ]
    FUNCTION_MATCHES_TABLE_COLUMNS = [
        McritTableColumn.SCORE,
        McritTableColumn.SHA256,
        # McritTableColumn.OFFSET,
        McritTableColumn.FAMILY_NAME,
        McritTableColumn.VERSION,
        McritTableColumn.SAMPLE_ID,
        McritTableColumn.FUNCTION_ID,
        McritTableColumn.PIC_HASH_MATCH,
        McritTableColumn.IS_LIBRARY,
    ]
    FUNCTION_NAMES_TABLE_COLUMNS = [
        McritTableColumn.FUNCTION_ID,
        McritTableColumn.SCORE,
        McritTableColumn.USER,
        McritTableColumn.FUNCTION_LABEL,
        # McritTableColumn.TIMESTAMP,
    ]
    OVERVIEW_TABLE_COLUMNS = [
        McritTableColumn.OFFSET,
        McritTableColumn.FAMILIES,
        McritTableColumn.SAMPLES,
        McritTableColumn.FUNCTIONS,
        McritTableColumn.IS_LIBRARY,
        McritTableColumn.SCORE_AND_LABEL,
    ]

    def __init__(self, version, get_setting=None):
        self.VERSION = version
        self._get_setting = get_setting
        self._defaults = {
            "mcritweb_username": "",
            "mcrit_server": "http://127.0.0.1:8000/",
            "mcritweb_api_token": "",
            "mcrit_request_timeout": "10",
            "sample_group_only": False,
            "auto_analyze_smda_on_startup": False,
            "use_smda_for_analysis": False,
            "submit_function_names_on_close": False,
            "blocks_filter_library_functions": False,
            "blocks_live_query": False,
            "blocks_min_size": "4",
            "function_filter_library_functions": False,
            "function_live_query": False,
            "function_min_score": "50",
            "overview_fetch_labels_automatically": False,
            "overview_filter_to_labels": False,
            "overview_filter_to_conflicts": False,
            "overview_min_score": "50",
        }
        # developer convenience to override settings without touching the disassembler's settings store
        override_path = os.path.join(PLUGIN_ROOT, "config_override.json")
        if os.path.exists(override_path):
            try:
                with open(override_path, "r") as override_file:
                    override_settings = json.load(override_file)
                    for key in self._defaults.keys():
                        self._defaults[key] = override_settings.get(key, self._defaults[key])
            except (json.JSONDecodeError, IOError):
                pass

    def _get(self, key):
        """Get a setting from the settings store, falling back to defaults on error.

        Args:
            key: Setting key to retrieve.

        Returns:
            The setting value or its default.
        """
        if self._get_setting is None:
            return self._defaults.get(key)
        try:
            return self._get_setting(key)
        except (KeyError, AttributeError, ValueError, TypeError, RuntimeError):
            return self._defaults.get(key)

    def _get_bool(self, key):
        """Get a setting and coerce it to boolean.

        Args:
            key: Setting key to retrieve.

        Returns:
            Boolean value of the setting.
        """
        value = self._get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def _get_int(self, key, default):
        value = self._get(key)
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    @property
    def MCRITWEB_USERNAME(self):
        """MCRITWeb username for authentication."""
        return self._get("mcritweb_username")

    @property
    def MCRIT_SERVER(self):
        """URL of the MCRIT server."""
        return self._get("mcrit_server")

    @property
    def MCRITWEB_API_TOKEN(self):
        """API token for MCRITWeb authentication."""
        return self._get("mcritweb_api_token")

    @property
    def MCRIT_REQUEST_TIMEOUT(self):
        """Timeout in seconds for MCRIT API requests."""
        return self._get_int("mcrit_request_timeout", 10)

    @property
    def SAMPLE_GROUP_ONLY(self):
        """Restrict matching results to samples in the current sample group."""
        return self._get_bool("sample_group_only")

    @property
    def AUTO_ANALYZE_SMDA_ON_STARTUP(self):
        """Auto-convert the database to an SMDA report on plugin startup."""
        return self._get_bool("auto_analyze_smda_on_startup")

    @property
    def USE_SMDA_FOR_ANALYSIS(self):
        """Also disassemble with SMDA itself instead of only exporting the disassembler's analysis."""
        return self._get_bool("use_smda_for_analysis")

    @property
    def SUBMIT_FUNCTION_NAMES_ON_CLOSE(self):
        """Submit updated function names to MCRIT when the database is closed."""
        return self._get_bool("submit_function_names_on_close")

    @property
    def BLOCKS_FILTER_LIBRARY_FUNCTIONS(self):
        """Filter out library functions in Block Scope Widget."""
        return self._get_bool("blocks_filter_library_functions")

    @property
    def BLOCKS_LIVE_QUERY(self):
        """Enable live query updates in Block Scope Widget."""
        return self._get_bool("blocks_live_query")

    @property
    def BLOCKS_MIN_SIZE(self):
        """Minimum block size for Block Scope Widget analysis."""
        return self._get_int("blocks_min_size", 4)

    @property
    def FUNCTION_FILTER_LIBRARY_FUNCTIONS(self):
        """Filter out library functions in Function Scope Widget."""
        return self._get_bool("function_filter_library_functions")

    @property
    def FUNCTION_LIVE_QUERY(self):
        """Enable live query updates in Function Scope Widget."""
        return self._get_bool("function_live_query")

    @property
    def FUNCTION_MIN_SCORE(self):
        """Minimum match score for Function Scope Widget."""
        return self._get_int("function_min_score", 50)

    @property
    def OVERVIEW_FETCH_LABELS_AUTOMATICALLY(self):
        """Auto-fetch labels in Function Overview Widget."""
        return self._get_bool("overview_fetch_labels_automatically")

    @property
    def OVERVIEW_FILTER_TO_LABELS(self):
        """Filter to labeled functions in Function Overview Widget."""
        return self._get_bool("overview_filter_to_labels")

    @property
    def OVERVIEW_FILTER_TO_CONFLICTS(self):
        """Filter to conflicting labels in Function Overview Widget."""
        return self._get_bool("overview_filter_to_conflicts")

    @property
    def OVERVIEW_MIN_SCORE(self):
        """Minimum match score for Function Overview Widget."""
        return self._get_int("overview_min_score", 50)
