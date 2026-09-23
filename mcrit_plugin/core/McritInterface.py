import json
import os
import threading
import traceback

import requests

from mcrit_plugin.core.minimcrit.client.McritClient import McritClient
from mcrit_plugin.core.minimcrit.storage.MatchingResult import MatchingResult

try:
    from smda.Disassembler import Disassembler
except Exception as exc:
    Disassembler = None
    _SMDA_IMPORT_ERROR = exc
else:
    _SMDA_IMPORT_ERROR = None


class McritInterface(object):
    def __init__(self, parent, backend):
        if Disassembler is None:
            raise ImportError(
                "SMDA not found, please install it (and its dependencies) as a python package to proceed!"
            ) from _SMDA_IMPORT_ERROR
        self.parent = parent
        self.backend = backend
        self.config = parent.config
        self._mcrit_server = self.config.MCRIT_SERVER
        self.mcrit_client = McritClient(self.config.MCRIT_SERVER)
        timeout_value = self.config.MCRIT_REQUEST_TIMEOUT
        if timeout_value and timeout_value > 0:
            self.mcrit_client.setTimeout(timeout_value)
        if self.config.MCRITWEB_API_TOKEN:
            self.mcrit_client.setApitoken(self.config.MCRITWEB_API_TOKEN)
        if self.config.MCRITWEB_USERNAME:
            self.mcrit_client.setUsername(self.config.MCRITWEB_USERNAME)
        # IDA 6.x Windows workaronud to avoid lost imports
        self.json = json
        self.os = os
        self.os_path = os.path

    def _getMcritServerAddress(self):
        return self._mcrit_server

    @staticmethod
    def _describeError(exc):
        """McritClient answers None for HTTP 4xx/5xx, so anything raised here is transport or payload."""
        if isinstance(exc, requests.exceptions.Timeout):
            return "request timed out"
        if isinstance(exc, requests.exceptions.ConnectionError):
            return "server unreachable"
        if isinstance(exc, requests.exceptions.RequestException):
            return "request error: %s" % exc
        return "unexpected %s: %s" % (type(exc).__name__, exc)

    def _reportFailure(self, operation, exc):
        traceback.print_exc()
        self.parent.local_widget.updateActivityInfo(
            "%s failed (%s)." % (operation, self._describeError(exc))
        )
        self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

    def _select_smda_backend(self, binary_info):
        """One of SMDA's own backend names, or None to let SMDA pick; an unknown name leaves the
        Disassembler without a backend instead of raising."""
        arch = (binary_info.architecture or "").lower()
        if "x86" in arch or "amd64" in arch or "i386" in arch or "intel" in arch:
            return "intel"
        if "aarch64" in arch or "arm64" in arch:
            return "aarch64"
        return None

    def convertToSmda(self):
        self.parent.local_widget.updateActivityInfo("Converting to SMDA report...")
        report = self.backend.export_smda_report()
        self.parent.local_widget.updateActivityInfo("Conversion to SMDA finished.")
        return report

    def convertToSmdaUsingSmda(self):
        self.parent.local_widget.updateActivityInfo("Converting to SMDA report using SMDA...")
        binary_info = self.backend.get_binary_info()
        backend = self._select_smda_backend(binary_info)
        if backend:
            self.parent.local_widget.updateActivityInfo(f"SMDA backend selected: {backend}")
        else:
            self.parent.local_widget.updateActivityInfo("SMDA backend selected: auto")
        try:
            smda_disassembler = Disassembler(backend=backend) if backend else Disassembler()
        except Exception as e:
            print(
                f"[MCRIT] Failed to initialize Disassembler with backend '{backend}', falling back to 'intel'. Error: {e}"
            )
            smda_disassembler = Disassembler(backend="intel")
        report = smda_disassembler._disassemble(binary_info, timeout=300)
        function_symbols = self.backend.get_function_symbols()
        for smda_function in report.getFunctions():
            if smda_function.offset in function_symbols:
                smda_function.function_name = function_symbols[smda_function.offset]
        self.parent.local_widget.updateActivityInfo("Conversion to SMDA finished.")
        return report

    def _check_connection_impl(self):
        try:
            mcrit_version = self.mcrit_client.getVersion()
            return mcrit_version, None
        except Exception as exc:
            traceback.print_exc()
            return None, exc

    def checkConnection(self, async_=False):
        self.parent.local_widget.updateActivityInfo(
            "Checking connection to server: %s" % self._getMcritServerAddress()
        )

        def apply_result(result):
            mcrit_version, err = result
            if mcrit_version:
                self.parent.local_widget.updateActivityInfo("Connection check successful!")
                self.parent.local_widget.updateServerInfo(
                    self._getMcritServerAddress(), version=mcrit_version
                )
            else:
                reason = (
                    "server rejected the request or sent no version"
                    if err is None
                    else self._describeError(err)
                )
                self.parent.local_widget.updateActivityInfo(
                    "Connection check failed (%s)." % reason
                )
                self.parent.local_widget.updateServerInfo(self._getMcritServerAddress())

        if async_:

            def runner():
                result = self._check_connection_impl()
                self.backend.run_on_ui_thread(lambda: apply_result(result))

            thread = threading.Thread(target=runner, daemon=True)
            thread.start()
            return

        apply_result(self._check_connection_impl())

    def querySampleSha256(self, sha256):
        self.parent.local_widget.updateActivityInfo("Querying for SHA256")
        try:
            sample_by_sha256 = self.mcrit_client.getSampleBySha256(sha256)
            if sample_by_sha256:
                self.parent.remote_sample_entry = sample_by_sha256
                self.parent.remote_sample_id = sample_by_sha256.sample_id
                self.parent.local_widget.updateActivityInfo(
                    "Success! Received remote Sample Entry."
                )
            else:
                self.parent.local_widget.updateActivityInfo("querySampleSha256 failed")
        except Exception as exc:
            self._reportFailure("querySampleSha256", exc)

    def uploadReport(self, report):
        self.parent.local_widget.updateActivityInfo(
            "Sending SMDA report to server %s" % self._getMcritServerAddress()
        )
        try:
            sample_entry, job_id = self.mcrit_client.addReport(report)
            if sample_entry:
                if job_id:
                    self.parent.local_widget.updateActivityInfo(
                        "Upload finished, remote sample_id is: %d (processing MinHashes as job_id: %s)"
                        % (sample_entry.sample_id, job_id)
                    )
                else:
                    self.parent.local_widget.updateActivityInfo(
                        "Upload finished, remote sample_id is: %d." % sample_entry.sample_id
                    )
                self.parent.remote_sample_entry = sample_entry
                self.parent.remote_sample_id = sample_entry.sample_id
                self.parent.local_widget.update()
            else:
                self.parent.local_widget.updateActivityInfo("Upload failed.")
        except Exception as exc:
            self._reportFailure("Upload", exc)

    def queryJobs(self, sample_id=None):
        """Fetch all jobs regarding Matches, optionally filter to a sample_id"""
        if sample_id is not None:
            self.parent.local_widget.updateActivityInfo(
                "Querying jobs for sample with id: %d" % self.parent.remote_sample_id
            )
        else:
            self.parent.local_widget.updateActivityInfo("Querying jobs.")
        try:
            # fetch jobs
            jobs = self.mcrit_client.getQueueData(filter="Matches")
            # check if we already have a match report for the sample id
            if sample_id is not None:
                jobs = [
                    job
                    for job in jobs
                    if "(" + str(sample_id) + ")" in job.parameters
                    or "(" + str(sample_id) + "," in job.parameters
                    or "," + str(sample_id) + "," in job.parameters
                    or "," + str(sample_id) + ")" in job.parameters
                ]
            if jobs:
                self.parent.local_widget.updateActivityInfo("Success! Fetched Jobs.")
            else:
                self.parent.local_widget.updateActivityInfo("No jobs available yet.")
            return jobs
        except Exception as exc:
            self._reportFailure("Job query", exc)

    def requestMatchingJob(self, sample_id, force_update=False):
        self.parent.local_widget.updateActivityInfo(
            "Tasking matching job for sample with id: %d" % self.parent.remote_sample_id
        )
        try:
            job_id = self.mcrit_client.requestMatchesForSample(
                sample_id,
                band_matches_required=2,
                force_recalculation=force_update,
                sample_group_only=self.config.SAMPLE_GROUP_ONLY,
            )
            if job_id:
                self.parent.local_widget.updateActivityInfo(
                    "Success! MatchingJob has ID: %s." % job_id
                )
                return job_id
            else:
                self.parent.local_widget.updateActivityInfo("Match query failed.")
        except Exception as exc:
            self._reportFailure("Match query", exc)
        return None

    def getMatchingJobById(self, job_id):
        self.parent.local_widget.updateActivityInfo("Querying result for job with id: %s" % job_id)
        try:
            matching_result = self.mcrit_client.getResultForJob(job_id)
            if matching_result:
                self.parent.matching_job_id = job_id
                self.parent.matching_report = MatchingResult.fromDict(matching_result)
                self.parent.local_widget.updateActivityInfo("Success! Downloaded MatchResult.")
            else:
                self.parent.local_widget.updateActivityInfo("Result query failed.")
        except Exception as exc:
            self._reportFailure("Result query", exc)

    def queryAllFamilyEntries(self):
        self.parent.local_widget.updateActivityInfo("Querying for FamilyEntries")
        try:
            family_entries = self.mcrit_client.getFamilies()
            if family_entries:
                self.parent.family_infos = {int(k): v for k, v in family_entries.items()}
                self.parent.local_widget.updateActivityInfo(
                    "Success! Received all remote FamilyEntries."
                )
            else:
                self.parent.local_widget.updateActivityInfo("queryAllFamilyEntries failed")
        except Exception as exc:
            self._reportFailure("queryAllFamilyEntries", exc)

    def querySmdaFunctionMatches(self, smda_report):
        try:
            functions = list(smda_report.getFunctions())
            if not functions:
                return None
            smda_function = functions[0]
            if smda_function.offset not in self.parent.function_matches:
                match_report_dict = self.mcrit_client.getMatchesForSmdaFunction(
                    smda_report,
                    exclude_self_matches=False,
                    sample_group_only=self.config.SAMPLE_GROUP_ONLY,
                )
                if match_report_dict:
                    self.parent.function_matches.update({smda_function.offset: match_report_dict})
                if match_report_dict:
                    match_report = MatchingResult.fromDict(match_report_dict)
                    matched_function_ids = [
                        match.matched_function_id for match in match_report.function_matches
                    ]
                    unknown_function_ids = [
                        fid
                        for fid in matched_function_ids
                        if fid not in self.parent.function_id_to_offset
                    ]
                    if unknown_function_ids:
                        function_entries = self.queryFunctionEntriesById(unknown_function_ids)
                        if function_entries:
                            for function_id, function_entry in function_entries.items():
                                self.parent.function_id_to_offset[function_id] = (
                                    function_entry.offset
                                )
                    return match_report
        except Exception as exc:
            self._reportFailure("querySmdaFunctionMatches", exc)

    def queryFunctionEntriesById(self, function_ids, with_label_only=False):
        """The entries by id ({} when none qualify), or None when the request failed."""
        try:
            function_entries = self.mcrit_client.getFunctionsByIds(
                function_ids, with_label_only=with_label_only
            )
        except Exception as exc:
            self._reportFailure("queryFunctionEntriesById", exc)
            return None
        if function_entries is None:
            return None
        if function_entries:
            if self.parent.matched_function_entries is None:
                self.parent.matched_function_entries = {}
            self.parent.matched_function_entries.update(function_entries)
        return function_entries

    def queryPicHashMatches(self, pichash):
        try:
            if pichash not in self.parent.pichash_matches:
                pichash_matches = self.mcrit_client.getMatchesForPicHash(pichash)
                if pichash_matches:
                    self.parent.pichash_matches.update({pichash: pichash_matches})
                pichash_match_summary = self.mcrit_client.getMatchesForPicHash(
                    pichash, summary=True
                )
                if pichash_match_summary:
                    self.parent.pichash_match_summaries.update({pichash: pichash_match_summary})
        except Exception as exc:
            self._reportFailure("queryPicHashMatches", exc)

    def queryAllSampleEntries(self):
        self.parent.local_widget.updateActivityInfo("Querying for SampleEntries")
        try:
            sample_entries = self.mcrit_client.getSamples()
            if sample_entries:
                self.parent.sample_infos = sample_entries
                self.parent.local_widget.updateActivityInfo(
                    "Success! Received all remote SampleEntries."
                )
            else:
                self.parent.local_widget.updateActivityInfo("queryAllSampleEntries query failed")
        except Exception as exc:
            self._reportFailure("queryAllSampleEntries", exc)

    def queryFunctionEntriesBySampleId(self, sample_id):
        self.parent.local_widget.updateActivityInfo("Querying for remote FunctionEntry mapping")
        try:
            functions_for_sample = self.mcrit_client.getFunctionsBySampleId(sample_id)
            if functions_for_sample:
                self.parent.remote_function_mapping = {
                    function_entry.function_id: function_entry
                    for function_entry in functions_for_sample
                }
                self.parent.local_widget.updateActivityInfo(
                    "Success! Fetched remote FunctionEntry mapping."
                )
            else:
                self.parent.local_widget.updateActivityInfo(
                    "queryFunctionEntriesBySampleId query failed."
                )
        except Exception as exc:
            self._reportFailure("queryFunctionEntriesBySampleId", exc)

    def queryFunctionEntryById(self, function_id):
        try:
            return self.mcrit_client.getFunctionById(function_id, with_xcfg=True)
        except Exception as exc:
            self._reportFailure("queryFunctionEntryById", exc)

    def querySampleEntryById(self, sample_id):
        try:
            return self.mcrit_client.getSampleById(sample_id)
        except Exception as exc:
            self._reportFailure("querySampleEntryById", exc)

    def getMatchesForPicBlockHash(self, picblockhash):
        try:
            return self.mcrit_client.getMatchesForPicBlockHash(picblockhash)
        except Exception as exc:
            self._reportFailure("getMatchesForPicBlockHash", exc)
