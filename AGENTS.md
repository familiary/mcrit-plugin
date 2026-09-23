# AGENTS.md — MCRIT plugins for IDA Pro and Binary Ninja

This repository ships two plugins for MCRIT (MinHash-based Code Relationship & Investigation Toolkit), built from one shared code base: one for **IDA Pro** (9.0+) and one for **Binary Ninja** (6.0+). Both provide a GUI for interactive code-similarity analysis against an **existing** MCRIT server: querying functions/blocks, syncing labels, and visualizing matches. They are *clients* of the MCRIT core service (see [mcrit](https://github.com/danielplohmann/mcrit)), not the server itself — the server runs elsewhere and is contacted over its REST API.

For the MCRIT methodology (PicHash/MinHash, LSH banding) see the [mcrit `AGENTS.md`](https://github.com/danielplohmann/mcrit/blob/main/AGENTS.md) and the [README](README.md).

## Repository layout

- `mcrit_plugin/ida/ida_mcrit.py` — IDA plugin entry point (registers actions, widgets, menus in IDA); `scripts/ida/package_plugin.py` places it at the archive root.
- `mcrit_plugin/ida/ida-plugin.json` — **HCLI/IDA plugin metadata**: the single source of truth for the IDA plugin `version` and the declarative `settings` list (mirrored by `mcrit_plugin/core/settings.json`); placed at the archive root by the packager and excluded from GitHub source archives.
- `mcrit_plugin/core/` — disassembler-independent plugin logic with **no GUI toolkit imports** (enforced by `tests/core/test_core_has_no_gui_imports.py`); `revision.py` reports the core commit.
  - `config.py` — `McritConfig`: **defaults** for every setting, type coercion, table layouts; reads values through a disassembler-specific getter.
  - `McritInterface.py` — orchestrates server communication, background jobs, UI-thread dispatch.
  - `McritClient` (under `mcrit_plugin/core/minimcrit/`) — the **internalized** MCRIT client + DTOs (the `mcrit` package is no longer a dependency; see "Vendored vs. internalized" below).
  - `Backend.py` — disassembler interface used by `McritInterface` and the widgets.
  - `minimcrit/`, `pylev/` — see "Vendored vs. internalized".
  - `ScoreColorProvider.py`, `McritTableColumn.py`, `HeadlessMcritContext.py` — helpers.
- `mcrit_plugin/ui_qt/` — Qt layer shared by IDA and Binary Ninja: `QtShim.py` (PySide6/PyQt5 selection), `ClassCollection.py`, `McritSession.py` (cross-widget state hosted by each frontend), `widgets/`.
- `mcrit_plugin/headless/` — `HeadlessBackend` (SMDA disassembles the input, labels in memory) for licence-free CI and scripting.
- `mcrit_plugin/ui_qt/widgets/` — Qt views (`MainWidget`, `FunctionMatchWidget`, `BlockMatchWidget`, `FunctionOverviewWidget`, `SampleInfoWidget`, `LocalInfoWidget`, dialogs).
- `mcrit_plugin/ida/` — `IdaBackend`, `SmdaGraphViewer`, and `config.py` (plugin `VERSION` plus the `ida-settings` binding).
- `mcrit_plugin/binja/` — Binary Ninja frontend: `BinjaBackend`, `BinjaSmdaInterface` (SMDA `BackendInterface` fed to SMDA's `IdaExporter`), `config.py` (Binary Ninja Settings registered from the `ida-plugin.json` declarations; `VERSION` from `plugin.json`), and `McritSidebar` (sidebar, UI actions, close hook). Root `plugin.json` / `__init__.py` / `requirements.txt` are the Binary Ninja manifest, entry point and dependencies; `scripts/ida/package_plugin.py` keeps `mcrit_plugin/binja` out of the IDA archive.
- `scripts/ida/` — packaging, metadata verification, IDA GUI/IDALib integration runners; `scripts/binja/` — Binary Ninja GUI integration runner; `scripts/common/` — settings verification, quality checks, fixture building, MCRIT seeding.
- `tests/core/` — pure-Python pytest suite (IDA/SMDA are stubbed in `tests/conftest.py`); `tests/ida/`, `tests/binja/` — integration tests run inside the disassemblers.
- `icons/` — resources; `docs/` — `config_override.json.template` and the Qt Designer mockup.

## Development setup

**Python:** the runtime floor is **Python 3.12**, the floor shared across the MCRIT ecosystem (`smda`, the co-dependency, requires it from its next release). IDA 9 bundles 3.12; the `scripts/` harnesses run under a separate venv of the same minor series. `pyproject.toml` sets ruff `target-version = "py312"` to match.

Install dependencies with the IDA-bundled or matching Python:

```bash
python -m pip install "smda>=4.3.10" "ida-settings>=3.5.1" requests
```

Install the plugin via HCLI (`hcli plugin install ...`) or by extracting a packaged ZIP into `$IDAUSR/plugins/mcrit-ida/` (see README).

## Common commands

Lint, tests, packaging and metadata checks are listed in
[`docs/development.md`](docs/development.md); run them before considering work done.

## Architecture primer

- **Entry** (`mcrit_plugin/ida/ida_mcrit.py`) registers IDA menus/actions/hotkeys and the MCRIT widget subviews.
- **`McritInterface`** owns the connection to the MCRIT server, runs long operations (convert IDB→SMDA, upload, query, match) off the UI thread, and dispatches results back to the widgets.
- **`McritClient`** (internalized under `mcrit_plugin/core/minimcrit/`) is the HTTP client speaking the MCRIT REST API. The plugin intentionally vendors a minified copy of the core client so it has no hard dependency on the `mcrit` package.
- **IDB→SMDA conversion** uses SMDA (optionally as the analysis backend via `use_smda_for_analysis`); results feed matching and label sync.
- **Widgets** render matches/blocks/functions/overview and are built on PySide6 through `QtShim`.

## Key concepts

These mirror the MCRIT core vocabulary (the plugin is a client of them):

- **PicHash / PicBlockHash** — exact, position-independent hashes (function- and block-level).
- **MinHash signature** — fuzzy similarity estimate derived from shingled code features.
- **Band / LSH** — candidate generation during fuzzy matching.
- **Family / Sample / Function** — the three-tier storage hierarchy on the server.
- **Label** — a server-side function name; the plugin can fetch, sync, and push function names.
- **Settings** — declared in `mcrit_plugin/ida/ida-plugin.json` and mirrored in `mcrit_plugin/core/settings.json`. IDA reads and writes them through `ida-settings`; Binary Ninja registers them with its Settings API from `mcrit_plugin/core/settings.json`.

## Code conventions

- Lint/format: `ruff` (line-length 100, `target-version = "py312"`, selects `E4/E7/E9/F/I`). Run `ruff format .` to auto-format. Vendored dirs (`mcrit_plugin/core/minimcrit`, `mcrit_plugin/core/pylev`, `icons`, `qt-designer-mockup`) are excluded from ruff.
- License: GPL-3.0-only.
- Do **not** introduce or log secrets/API tokens.

## Agent guardrails

- **Never** run `git commit`, `git push`, or open a PR unless explicitly instructed.
- **Never** commit secrets: `mcritweb_api_token`, `mcritweb_username`, `ida-config.json`, or a `config_override.json` containing credentials. These must stay out of the tree.
- **Settings & version sync** (this is the easy-to-break part):
  - Settings are **declared** in `mcrit_plugin/ida/ida-plugin.json` (`settings` array, mirrored in `mcrit_plugin/core/settings.json`) and have **defaults** in `mcrit_plugin/core/config.py` (`McritConfig._defaults`). These two must stay in sync; `verify_settings_sync.py` enforces it.
  - Where each plugin's `version` is declared, what has to agree with it, and the changelog entry every shipped change needs are in [`RELEASING.md`](RELEASING.md). **Do not bump either version unless explicitly asked.**
  - Always run `verify_metadata_sync.py` and `verify_settings_sync.py` after touching either file.
- **Testing**: run `ruff format --check`, `ruff check`, and `python -m pytest tests` before considering work complete. The pure pytest suite is secret-free and runs in CI on every push/PR.
- **IDA-licensed integration tests** (`.github/workflows/ida-tests.yml`) require a licensed IDA Pro and the `IDA_LICENSE_ID`/`HCLI_API_KEY` secrets. They are **not** available to fork PRs and must **not** be run by default. They are referenced here for completeness only; drive them via manual workflow dispatch or the local `scripts/ida/run_idalib_integration.py` / `scripts/ida/run_gui_integration.py` harnesses when a licensed IDA is present.
- **Vendored vs. internalized**:
  - `mcrit_plugin/core/pylev` is a third-party vendored library. Do **not** edit it.
  - `mcrit_plugin/core/minimcrit` is the *minified* MCRIT API surface internalized for this plugin. Enhancing it (e.g. exposing more functionality) is allowed, **but its `McritClient` interface must not deviate from the core `mcrit` package's `McritClient`** unless the core client is enhanced in lockstep. Keep the two aligned.

## Related repositories (reference only)

- [mcrit](https://github.com/danielplohmann/mcrit) — core server, worker, Python client, CLI (this plugin is a client of it).
- [mcrit-web](https://github.com/fkie-cad/mcritweb) — Flask browser front-end + user management.
- [docker-mcrit](https://github.com/danielplohmann/docker-mcrit) — containerized full-stack deployment.
- [mcrit-data](https://github.com/danielplohmann/mcrit-data) — ready-to-use reference data.
