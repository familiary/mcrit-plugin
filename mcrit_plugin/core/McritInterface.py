import threading
import traceback
from contextlib import contextmanager

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

# matching jobs by how many of their leading arguments name samples; MCRIT passes these
# positionally and the matching knobs by keyword, so a knob is never read as a sample id
_SAMPLE_MATCHING_METHODS = {
    "getMatchesForSample": 1,
    "getMatchesForSampleVs": 2,
    # a cross compare's part for one sample, with the others as a list
    "getMatchesForSampleVsGroup": 2,
}


def _matchesSample(job, sample_id):
    """Whether job is a matching job that names sample_id among its samples."""
    count = _SAMPLE_MATCHING_METHODS.get(job.method)
    if count is None:
        return False
    for argument in job.arguments[:count]:
        for value in argument if isinstance(argument, list) else [argument]:
            # int() as Job.sample_id reads them, whatever type the server stored
            try:
                if int(value) == sample_id:
                    return True
            except (TypeError, ValueError):
                continue
    return False


class McritInterface(object):
    def __init__(self, parent, backend):
        if Disassembler is None:
            raise ImportError(
                "SMDA not found, please install it (and its dependencies) as a python package to proceed!"
            ) from _SMDA_IMPORT_ERROR
        self.parent = parent
        self.backend = backend
        self.config = parent.config
        self._cache_lock = threading.Lock()
        self._remote_info_lock = threading.Lock()
        self._check_id = 0
        # a switch tests for held data, and an answer is checked and stored, under this lock: the
        # switch then either sees the stored answer and waits, or the answer sees the switch
        self._switch_lock = threading.Lock()
        self._server_generation = 0
        self._mcrit_server = None
        self._buildClient(self._readConnectionSettings())

    def _readConnectionSettings(self):
        return (
            self.config.MCRIT_SERVER,
            self.config.MCRIT_REQUEST_TIMEOUT,
            self.config.MCRITWEB_API_TOKEN,
            self.config.MCRITWEB_USERNAME,
        )

    def _buildClient(self, connection_settings):
        server, timeout, api_token, username = connection_settings
        client = McritClient(server)
        # setTimeout maps 0 to no limit; skipping it would keep the client's 10 s connect timeout
        client.setTimeout(timeout)
        if api_token:
            client.setApitoken(api_token)
        if username:
            client.setUsername(username)
        self._connection_settings = connection_settings
        # a connection check started before this client answers for nothing any more
        self._check_id += 1
        # requests already running keep the client they started with; set before the generation
        # moves, as _pinConnection reads the two without the lock
        self.mcrit_client = client
        if server != self._mcrit_server:
            self._mcrit_server = server
            self._server_generation += 1

    def _pinConnection(self):
        """The client a request works with and the server generation that tells whether its answer
        still belongs to the session. Read in this order, a switch in between can only make an
        answer from the new server look stale, never one from the old server look current."""
        generation = self._server_generation
        return self.mcrit_client, generation

    def _isStale(self, generation):
        """True, after saying so, when the server changed while the request ran."""
        if generation == self._server_generation:
            return False
        self.parent.local_widget.updateActivityInfo(
            "Dropped an answer from the previous server; the server changed meanwhile."
        )
        return True

    @contextmanager
    def _storing(self, generation):
        """Yields whether an answer still belongs to the session; store it inside the block."""
        with self._switch_lock:
            yield not self._isStale(generation)

    def _holdsServerData(self):
        parent = self.parent
        return bool(
            parent.remote_sample_id is not None
            or parent.remote_sample_entry is not None
            or parent.matching_report is not None
            or parent.matched_function_entries
            or parent.function_matches
            or parent.blockhash_matches
            or parent.sample_infos is not None
            or parent.family_infos is not None
        )

    def reloadSettings(self, recheck=False):
        """Pick up changed connection settings and check the connection again; UI thread only.

        With recheck, the connection is checked even when nothing changed. A new server is only
        taken while the session holds nothing from the current one, whose ids mean nothing there;
        until then the session keeps the current server's token and username and takes only the new
        timeout. Returns the server waiting for a reopen, or None.
        """
        connection_settings = self._readConnectionSettings()
        waiting_server = None
        with self._switch_lock:
            if connection_settings[0] != self._mcrit_server and self._holdsServerData():
                waiting_server = connection_settings[0]
                server, _timeout, api_token, username = self._connection_settings
                connection_settings = (server, connection_settings[1], api_token, username)
            changed = connection_settings != self._connection_settings
            if changed:
                self._buildClient(connection_settings)
        if changed:
            self.checkConnection(async_=True)
        elif recheck:
            self.checkConnection(async_=True)
        return waiting_server

    @property
    def server(self):
        """The server the session works with."""
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

    @staticmethod
    def _logTraceback(exc):
        if not isinstance(exc, requests.exceptions.RequestException):
            traceback.print_exc()

    def _reportFailure(self, operation, exc):
        self._logTraceback(exc)
        self.parent.local_widget.updateActivityInfo(
            "%s failed (%s)." % (operation, self._describeError(exc))
        )
        self.parent.local_widget.updateServerInfo(self.server)

    def _select_smda_backend(self, binary_info):
        """One of SMDA's own backend names, or None for SMDA's default; an unknown name leaves the
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

    def _check_connection_impl(self, client=None):
        try:
            mcrit_version = (client or self.mcrit_client).getVersion()
            return mcrit_version, None
        except Exception as exc:
            self._logTraceback(exc)
            return None, exc

    def checkConnection(self, async_=False):
        self.parent.local_widget.updateActivityInfo(
            "Checking connection to server: %s" % self.server
        )
        self.parent.local_widget.updateServerInfo(self.server, version="checking...")
        client = self.mcrit_client
        self._check_id += 1
        check_id = self._check_id

        def apply_result(result):
            if check_id != self._check_id:
                # a newer check or other settings came since; that one reports instead
                return
            mcrit_version, err = result
            if mcrit_version:
                self.parent.local_widget.updateActivityInfo("Connection check successful!")
                self.parent.local_widget.updateServerInfo(self.server, version=mcrit_version)
            else:
                reason = (
                    "server rejected the request or sent no version"
                    if err is None
                    else self._describeError(err)
                )
                hint = (
                    " The server is still the default one, use %s to change it."
                    % self.backend.settings_location
                    if self.config.isDefaultServer(self.server)
                    else ""
                )
                self.parent.local_widget.updateActivityInfo(
                    "Connection check failed (%s).%s" % (reason, hint)
                )
                self.parent.local_widget.updateServerInfo(self.server)

        if async_:

            def runner():
                result = self._check_connection_impl(client)
                self.backend.run_on_ui_thread(lambda: apply_result(result))

            thread = threading.Thread(target=runner, daemon=True)
            thread.start()
            return

        apply_result(self._check_connection_impl(client))

    def querySampleSha256(self, sha256):
        self.parent.local_widget.updateActivityInfo("Querying for SHA256")
        client, generation = self._pinConnection()
        try:
            sample_by_sha256 = client.getSampleBySha256(sha256)
            with self._storing(generation) as current:
                if not current:
                    return
                if sample_by_sha256:
                    self.parent.remote_sample_entry = sample_by_sha256
                    self.parent.remote_sample_id = sample_by_sha256.sample_id
            if sample_by_sha256:
                self.parent.local_widget.updateActivityInfo(
                    "Success! Received remote Sample Entry."
                )
            else:
                self.parent.local_widget.updateActivityInfo("querySampleSha256 failed")
        except Exception as exc:
            self._reportFailure("querySampleSha256", exc)

    def uploadReport(self, report):
        self.parent.local_widget.updateActivityInfo(
            "Sending SMDA report to server %s" % self.server
        )
        client, generation = self._pinConnection()
        try:
            sample_entry, job_id = client.addReport(report) or (None, None)
            with self._storing(generation) as current:
                if not current:
                    return
                if sample_entry:
                    self.parent.remote_sample_entry = sample_entry
                    self.parent.remote_sample_id = sample_entry.sample_id
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
            # fetch jobs; the server narrows them by the sample id as text, which also matches
            # other numbers, and older servers do not select by sample_ids, so the exact test
            # below stays
            jobs = self.mcrit_client.getQueueData(
                filter="Matches" if sample_id is None else str(sample_id)
            )
            if jobs is None:
                self.parent.local_widget.updateActivityInfo("Job query failed.")
                return None
            # check if we already have a match report for the sample id
            if sample_id is not None:
                jobs = [job for job in jobs if _matchesSample(job, sample_id)]
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
        client, generation = self._pinConnection()
        try:
            matching_result = client.getResultForJob(job_id)
            matching_report = MatchingResult.fromDict(matching_result) if matching_result else None
            with self._storing(generation) as current:
                if not current:
                    return
                if matching_report is not None:
                    self.parent.matching_job_id = job_id
                    self.parent.matching_report = matching_report
            if matching_report is not None:
                self.parent.local_widget.updateActivityInfo("Success! Downloaded MatchResult.")
            else:
                self.parent.local_widget.updateActivityInfo("Result query failed.")
        except Exception as exc:
            self._reportFailure("Result query", exc)

    def ensureRemoteInformation(self):
        """Download the family and sample lists unless the session has them. Callable from several
        threads: one downloads while the others wait for it instead of repeating it."""
        with self._remote_info_lock:
            # the two lists are independent, so they download side by side
            downloads = []
            if self.parent.family_infos is None:
                downloads.append(threading.Thread(target=self.queryAllFamilyEntries, daemon=True))
            if self.parent.sample_infos is None:
                downloads.append(threading.Thread(target=self.queryAllSampleEntries, daemon=True))
            for download in downloads:
                download.start()
            for download in downloads:
                download.join()
        return self.parent.family_infos is not None and self.parent.sample_infos is not None

    def queryAllFamilyEntries(self):
        self.parent.local_widget.updateActivityInfo("Querying for FamilyEntries")
        client, generation = self._pinConnection()
        try:
            family_entries = client.getFamilies()
            # None is a failed request; an empty dict is a server without families
            with self._storing(generation) as current:
                if not current:
                    return
                if family_entries is not None:
                    self.parent.family_infos = {int(k): v for k, v in family_entries.items()}
            if family_entries is not None:
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
            client, generation = self._pinConnection()
            if smda_function.offset not in self.parent.function_matches:
                match_report_dict = client.getMatchesForSmdaFunction(
                    smda_report, exclude_self_matches=False
                )
                with self._storing(generation) as current:
                    if not current:
                        return None
                    if match_report_dict:
                        self.parent.function_matches.update(
                            {smda_function.offset: match_report_dict}
                        )
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
                        function_entries = self.queryFunctionEntriesById(
                            unknown_function_ids, connection=(client, generation)
                        )
                        with self._storing(generation) as current:
                            if current and function_entries:
                                for function_id, function_entry in function_entries.items():
                                    self.parent.function_id_to_offset[function_id] = (
                                        function_entry.offset
                                    )
                    return match_report
        except Exception as exc:
            self._reportFailure("querySmdaFunctionMatches", exc)

    def queryFunctionEntriesById(self, function_ids, with_label_only=False, connection=None):
        """The entries by id, or None when the request raised or the server changed meanwhile;
        McritClient answers {} both when none qualify and when the server rejects the request."""
        client, generation = connection or self._pinConnection()
        try:
            function_entries = client.getFunctionsByIds(
                function_ids, with_label_only=with_label_only
            )
        except Exception as exc:
            self._reportFailure("queryFunctionEntriesById", exc)
            return None
        if function_entries is None:
            return None
        with self._storing(generation) as current:
            if not current:
                return None
            if function_entries:
                # requests run on worker threads while the UI iterates the cache: swap in a new dict
                with self._cache_lock:
                    merged = dict(self.parent.matched_function_entries or {})
                    merged.update(function_entries)
                    self.parent.matched_function_entries = merged
        return function_entries

    def queryAllSampleEntries(self):
        self.parent.local_widget.updateActivityInfo("Querying for SampleEntries")
        client, generation = self._pinConnection()
        try:
            sample_entries = client.getSamples()
            with self._storing(generation) as current:
                if not current:
                    return
                if sample_entries is not None:
                    self.parent.sample_infos = sample_entries
            if sample_entries is not None:
                self.parent.local_widget.updateActivityInfo(
                    "Success! Received all remote SampleEntries."
                )
            else:
                self.parent.local_widget.updateActivityInfo("queryAllSampleEntries query failed")
        except Exception as exc:
            self._reportFailure("queryAllSampleEntries", exc)

    def queryRemoteFunction(self, function_id):
        """(function entry with its CFG, its SmdaFunction, its sample entry), or None after reporting
        why; touches no widget, so it can run off the UI thread. The sample entry comes from the
        downloaded sample list when that has it."""
        client, generation = self._pinConnection()
        try:
            function_entry = client.getFunctionById(function_id, with_xcfg=True)
            if function_entry is None:
                self.parent.local_widget.updateActivityInfo(
                    f"Failed to fetch function entry {function_id}."
                )
                return None
            sample_infos = self.parent.sample_infos
            sample_entry = (
                sample_infos.get(function_entry.sample_id)
                if isinstance(sample_infos, dict)
                else None
            )
            if sample_entry is None:
                sample_entry = client.getSampleById(function_entry.sample_id)
            if sample_entry is None:
                self.parent.local_widget.updateActivityInfo(
                    f"Failed to fetch sample entry {function_entry.sample_id}."
                )
                return None
            if self._isStale(generation):
                return None
            # a malformed CFG raises here; the widgets then still get their None answer
            return function_entry, function_entry.toSmdaFunction(), sample_entry
        except Exception as exc:
            # the reason stays the last activity message
            self._reportFailure(f"Fetching function {function_id} for the graph viewer", exc)
            return None

    def getMatchesForPicBlockHash(self, picblockhash):
        """The matches, or None when the request failed or the server changed meanwhile; the
        widgets keep None out of the session's cache."""
        client, generation = self._pinConnection()
        try:
            matches = client.getMatchesForPicBlockHash(picblockhash)
            return None if self._isStale(generation) else matches
        except Exception as exc:
            self._reportFailure("getMatchesForPicBlockHash", exc)
