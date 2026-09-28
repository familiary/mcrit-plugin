# Changelog

All notable changes to both plugins are documented in this file, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [RELEASING.md](RELEASING.md) states what
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) covers for each plugin, and how and when
to add an entry. Release headings carry the IDA plugin's version; an entry that names IDA or Binary
Ninja applies to that plugin only.

## [Unreleased]

## [2.0.0] - 2026-09-18

### Added

- IDA releases are now cut by pushing an `ida-vX.Y.Z` tag (formerly `vX.Y.Z`), gated on the
  version strings, this file and CI, with pre-release tags (`ida-v1.2.0rc1`) marked as such. See
  [RELEASING.md](RELEASING.md).
- Binary Ninja support from the same repository: a native sidebar with the same toolbar and tabs as
  in IDA, SMDA reports exported from Binary Ninja's own analysis, settings under Settings → MCRIT
  with the API token kept in the system keychain, label import as one undo step, and remote CFGs as
  graph reports. Requires Binary Ninja 6.0 (build 10601) and is released separately through the
  extension manager; see `RELEASING.md`.
- The start message shows the core commit the plugin was built from, so a report names the exact
  code a user runs.

### Changed

- A repository checkout is no longer an IDA plugin directory; install the packaged ZIP, through
  HCLI or by hand. This is why this release is 2.0.0. The ZIP layout is unchanged
  (`ida-plugin.json` and `ida_mcrit.py` at the root), and existing settings keys still apply.
  Inside, the code moved into one `mcrit_plugin` package shared by both plugins.
- IDA releases are never marked as the latest GitHub release, so the Binary Ninja extension manager
  always reads the Binary Ninja release.
- `ida-plugin.json` names the repository's new home, https://github.com/familiary/mcrit-plugin.
- Cursor tracking in the Hex-Rays pseudocode view reads the current function from the open view
  instead of decompiling it again.
- In IDA, the SMDA export runs behind a wait box, and a failed export shows a warning and logs
  the traceback to the Output window instead of raising out of the button handler.
- A failed request to the MCRIT server says why (timed out, server unreachable, request error)
  instead of reporting a connection error, and an unexpected error logs its traceback.
- The upload offered on close sends the converted report with the current function names patched
  in, instead of exporting the database again, so closing never re-runs the analysis. Functions
  created after the last Convert are not in that upload, and a name reset to the default keeps
  its previous name there; convert again to include them.
- In IDA, a label import is one undo step instead of one per function, and applying a label from
  the Function Scope table is an undo step of its own.
- The automatic label fetch (`overview_fetch_labels_automatically`) asks only for matched functions
  it has not asked about yet; the Fetch Labels button still fetches labels for all of them.
- The activity line shows the local time instead of a UTC timestamp.
- Copying uses Qt's clipboard instead of the bundled `pyperclip`. On Linux without a clipboard
  manager, copied text is lost when IDA or Binary Ninja exits.
- Block Scope leaves blocks below the minimum size out of its queries, so their matches no longer
  count in the header totals.
- A failed Function Scope query clears the table and says so, instead of leaving the previous
  function's matches in place.
- The release history moved out of `README.md` into this file; the entries below are unchanged.
- CI and the release workflow run on Python 3.12, the floor MCRIT (since 1.10.0) and MCRITweb
  require; `smda` still supports 3.11 and plans to drop it. IDA 9 bundles 3.12 alongside 3.11;
  nothing in the plugin needed 3.12.
- The IDA integration workflow now ends in a "Licensed IDA result" check that reports when the
  licensed job could not run (a pull request from a fork, or missing licence secrets) and says
  why, instead of the job silently reporting `skipped` and the pull request looking green. It
  warns rather than fails, because a fork cannot obtain the licence secrets; a genuine failure of
  the licensed job is still red on that job.

### Removed

- The `sample_group_only` setting. MCRIT takes it for neither a matching job nor a function query,
  so with it on every matching job and every Function Scope query failed, and MCRITweb drops it.
  A value stored by an earlier version stays in `ida-config.json` and is ignored.

### Fixed

- Releases get their Windows offline dependency bundles again. The bundle workflow listened for
  published releases, which a release created by the release workflow never triggers, so 1.1.7
  to 1.1.10 shipped without them; the release workflow now calls it directly.
- Function and Block Scope showed "unknown" for every sample hash when the sample list could not
  be fetched at Convert. They fetch it again, and say "Remote family/sample info unavailable" when
  that fails too.
- The Sample Match Summary was not refreshed after a result was fetched, and its PicHash and
  MinHash columns were swapped.
- The Function Overview kept the score range of the first result it showed.
- After sorting the Function Overview, Import Labels applied each label to a different function,
  and after sorting the result chooser loaded a different job than the one selected.
- Function Scope queried functions of exactly 10 instructions, which MCRIT does not MinHash and
  answers with a server error; it now needs more than 10.
- Cursor moves before Convert were ignored, so Query Current Function and Query Current Block
  right after Convert found no current function until the cursor moved again.
- A failed PicBlockHash query read as "no matches" for the rest of the session. It is retried on
  the next visit, and the rest of that visit's lookups are skipped instead of each waiting out the
  same timeout.
- A failed job query opened the result chooser, which then said no matching results existed.
- Sample Info kept showing a family picked for an earlier result even when the next result has no
  match in it; it falls back to the best family then.
- The hover hint of the IDA graph view showed a placeholder text; it shows the block's offset.
- `config_override.json` applied only when the settings store failed, which with ida-settings is
  never, since every key has a declared default. It now takes precedence over the settings store,
  so check an existing copy: every key in it applies. The plugin prints the keys it forces when it
  loads, the template in the IDA ZIP shows two example keys instead of all of them, and boolean
  values given as strings are read as their value (only `sample_group_only` was converted before,
  so `"false"` switched any other option on).
- Block Scope said "Live Function Queries are deactivated" when its own live queries were off.
- Sorting Function Scope's match table by offset raised an exception inside Qt's sort, because the
  offsets are hex; under PySide6 6.11 that crashes the Python process. Offsets now sort by value.
- Converting with SMDA selects SMDA's `aarch64` backend for AArch64 databases instead of `arm`,
  which SMDA does not have. Other non-x86 architectures still fail, since SMDA does not support
  them.

### Security

- The offline-dependency workflow no longer expands the release tag inside its scripts (a tag
  name is attacker-influenced text in a workflow that runs with write permissions) and no longer
  keeps the checkout's credentials on the runner.

## [1.1.10] - 2026-09-16

### Fixed

- Function Scope returning no matches for every function after the first, on SMDA 4.8 and later.
  `SmdaReport.getFunctions()` caches its result there, and the plugin reused a single outline
  report across queries while only swapping its `xcfg`, so every query after the first
  re-submitted the first function. A fresh outline is now built per query.
- The outline now follows a replaced local report, so an upload after renaming no longer carries
  the previous report's metadata.

## Older releases

Recorded as they were written in the README at the time, newest first.

### v1.1.9 (2026-08-04)
- Matching reports now load ~7x faster (2.08s -> 0.29s on a 220k-match report), as the bundled minimcrit `MatchingResult.fromDict` no longer deep-copies the match lists for filtering. They are derived lazily as shallow copies on first access instead, mirroring the change in MCRIT 1.5.3.
- Added `MatchingResult.resetFilters()`, so a report can be re-filtered without accumulating previous filters.

### v1.1.8 (2026-07-15)
- Isolated MCRIT4IDA loggers by configuring them with their own handler instead of relying on IDA's shared root logger.
- Stopped bundled minimcrit modules from calling `logging.basicConfig()` at import time.
- Added a regression test for the case where another IDA plugin has already configured the root logger.

### v1.1.7 (2026-05-11)
- Better guarding of remote metadata
- Extensive testing for config parsing and McritClient communication
- Expose sample-group-only matching setting

### v1.1.6 (2026-03-23)
- Updated HCLI-facing plugin metadata for release packaging, including the `1.1.6` version, `IDA 9.0+` minimum, repository URL, and request-timeout setting.
- Added repo-local packaging and validation scripts for metadata sync, settings sync, Ruff checks, and minimal plugin ZIP creation.
- Added validation/release GitHub Actions to lint both the repo and packaged ZIP, publish `mcrit-ida-<version>.zip`, and attach offline dependency bundles to published releases.
- Switched the offline dependency workflow to run from published releases so wheelhouse bundles attach to the canonical release instead of tag pushes alone.
- Expanded the README with first-time HCLI setup, local ZIP installs, headless configuration examples, and manual installation steps without HCLI.

### v1.1.5 (2026-02-27)
- Added configurable MCRIT request timeouts via `mcrit_request_timeout` and aligned numeric setting defaults with the plugin settings metadata.
- Refactored `McritClient` HTTP calls through shared request helpers and added centralized timeout support via `setTimeout()`.
- Moved the initial server connection check off the UI thread and improved startup status reporting.
- Added architecture-aware SMDA backend selection with logging and fallback handling during IDB-to-SMDA conversion.
- Hardened `McritInterface` connection error handling and UI-thread dispatch for background updates.
- Guarded remote metadata lookups and empty/missing response data in `BlockMatchWidget`, `FunctionMatchWidget`, and `SampleInfoWidget` to avoid crashes when server state is incomplete.
- Added safety checks before applying labels in `FunctionOverviewWidget` when no label column is configured or no labels have been fetched.
- Fixed job dialog preselection when the selected row index is `0`.
- Removed the custom graph close action from `SmdaGraphViewer` to avoid the `AttributeError` path there.
- Cleaned up vendored `pyperclip` compatibility handling for newer Python versions and removed stray debug/formatting issues from the batch.

### v1.1.4 (2026-01-30)
- added Github action to build dependency packages to facilitate installation in offline environments.
- Removed the mcrit package dependency by internalizing McritClient and required DTOs.
- Restored plugin hotkey handler and added a close action to the graph context menu.
- Improved resilience for missing or empty match data and guarded SMDA import paths.
- Hardened UI flows around function labels and form handling.
- Dev/CI: Added Ruff config + GitHub Action and reformatted the codebase.

### v1.1.3 (2026-01-28)
- Significantly improved usablity of FunctionOverviewWidget by being able to deconflict multiple candidate labels.

### v1.1.2 (2026-01-19)
- Optionally use SMDA as backend analysis engine (consistency towards MCRIT server), even when in IDA Pro.

### v1.1.1 (2026-01-15)
- Now coloring results in BlockMatch (by frequency) and FunctionMatch (by score) widgets
- Can now display offsets of matched functions in FunctionMatchWidget

### v1.1.0 (2025-12-30)
- Full HCLI Plugin Manager support.
- Migrated configuration to `ida-settings`.
- Code quality improvements.
- Strict HCLI compliance.

### v1.0.0 (2025-12-22)
- Initial standalone release.
- IDA 9.2 (PySide6) compatibility.

[Unreleased]: https://github.com/familiary/mcrit-plugin/compare/ida-v2.0.0...HEAD
[2.0.0]: https://github.com/familiary/mcrit-plugin/compare/v1.1.10...ida-v2.0.0
[1.1.10]: https://github.com/familiary/mcrit-plugin/compare/v1.1.9...v1.1.10
