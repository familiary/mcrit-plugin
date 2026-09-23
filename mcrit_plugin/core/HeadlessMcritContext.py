"""Minimal non-GUI state container for IDALib integration tests."""

from __future__ import annotations

from mcrit_plugin.core.McritInterface import McritInterface


class HeadlessActivity:
    """Collect status updates made by :class:`McritInterface` without Qt."""

    def __init__(self):
        self.messages = []
        self.server = None

    def updateActivityInfo(self, message):
        self.messages.append(message)

    def updateServerInfo(self, server, version=None):
        self.server = (server, version)

    def update(self):
        return None


class HeadlessMcritContext:
    """State surface required by MCRIT operations outside the IDA GUI."""

    def __init__(self, config, backend):
        self.config = config
        self.local_widget = HeadlessActivity()
        self.local_smda_report = None
        # Mirrors McritSession: the outline is cached as a dict and rebuilt per query.
        self.local_smda_report_outline = None
        self._outline_source = None
        self.remote_sample_id = None
        self.remote_sample_entry = None
        self.matching_job_id = None
        self.matching_report = None
        self.matched_function_entries = None
        self.remote_function_mapping = {}
        self.sample_infos = {}
        self.family_infos = None
        self.function_id_to_offset = {}
        self.function_matches = {}
        self.pichash_matches = {}
        self.pichash_match_summaries = {}
        self.mcrit_interface = McritInterface(self, backend)
