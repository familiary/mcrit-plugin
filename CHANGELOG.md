# Changelog

All notable changes to both plugins are documented in this file, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [RELEASING.md](RELEASING.md) states what
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) covers for each plugin, and how and when
to add an entry.

## [Unreleased]

## [2.0.0] - 2026-09-18

### Added

- IDA releases are now cut by pushing an `ida-vX.Y.Z` tag, gated on the version strings, this file
  and CI, with pre-release tags (`ida-v1.2.0rc1`) marked as such. See
  [RELEASING.md](RELEASING.md).
- A pull request that changes the shipped plugin files has to add a `CHANGELOG.md` entry or carry
  the `no-changelog` label; CI checks it.
- Binary Ninja support from the same repository: a native sidebar with the same toolbar and tabs as
  in IDA, SMDA reports exported from Binary Ninja's own analysis, settings under Settings → MCRIT
  with the API token kept in the system keychain, label import as one undo step, and remote CFGs as
  graph reports. Requires Binary Ninja 6.0 (build 10601) and is released separately through the
  extension manager; see `RELEASING.md`.
- The start message shows the core commit the plugin was built from, so a report names the exact
  code a user runs.

### Changed

- IDA release tags are now `ida-vX.Y.Z` instead of `vX.Y.Z`, and IDA releases are never marked as
  the latest GitHub release, so the Binary Ninja extension manager always reads the Binary Ninja
  release.
- The code moved into one `mcrit_plugin` package: `core` (no GUI imports), `ui_qt` (the shared
  widgets), `ida`, `binja` and `headless`. The IDA ZIP layout is unchanged (`ida-plugin.json` and
  `ida_mcrit.py` at the root), and existing settings keys and `config_override.json` still apply.
  A repository checkout is no longer an IDA plugin directory; install the packaged ZIP.
- Cursor tracking in the Hex-Rays pseudocode view reads the current function from the open view
  instead of decompiling it again.
- In IDA, the SMDA export runs behind a wait box, and a failed export shows a warning and logs
  the traceback to the Output window instead of raising out of the button handler.
- The release history moved out of `README.md` into this file; the entries below are unchanged.
  `verify_metadata_sync.py` now reads the latest release heading from here.
- The offline-dependency workflow no longer expands the release tag inside its scripts (a tag
  name is attacker-influenced text in a workflow that runs with write permissions) and no longer
  keeps the checkout's credentials on the runner.
- CI and the release workflow run on Python 3.12, matching the floor the rest of the MCRIT
  ecosystem now shares (`smda`, which the plugin needs in IDA's interpreter, requires 3.12 from
  its next release). IDA 9 bundles 3.12 alongside 3.11; nothing in the plugin needed 3.12.
- The IDA integration workflow now ends in a "Licensed IDA result" check that reports when the
  licensed job could not run (a pull request from a fork, or missing licence secrets) and says
  why, instead of the job silently reporting `skipped` and the pull request looking green. It
  warns rather than fails, because a fork cannot obtain the licence secrets; a genuine failure of
  the licensed job is still red on that job.

### Fixed

- Releases get their Windows offline dependency bundles again. The bundle workflow listened for
  published releases, which a release created by the release workflow never triggers, so 1.1.7
  to 1.1.9 shipped without them; the release workflow now calls it directly.

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

[Unreleased]: https://github.com/danielplohmann/mcrit-plugin/compare/ida-v2.0.0...HEAD
[2.0.0]: https://github.com/danielplohmann/mcrit-plugin/compare/v1.1.10...ida-v2.0.0
[1.1.10]: https://github.com/danielplohmann/mcrit-plugin/compare/v1.1.9...v1.1.10
