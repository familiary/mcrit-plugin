# Development

## Layout

```text
mcrit-plugin/
├── plugin.json              # Binary Ninja manifest (must stay at the root)
├── __init__.py              # Binary Ninja entry point (must stay at the root)
├── requirements.txt         # Binary Ninja dependencies (must stay at the root)
├── mcrit_plugin/
│   ├── core/                # MCRIT client, settings, Backend interface, SMDA conversion; no GUI imports
│   │   ├── minimcrit/       # internalized MCRIT REST client
│   │   └── pylev/           # vendored Levenshtein helper (do not edit)
│   ├── ui_qt/               # Qt widgets shared by IDA and Binary Ninja
│   ├── ida/                 # ida-plugin.json, ida_mcrit.py, IDA backend, graph viewer
│   ├── binja/               # Binary Ninja backend, settings, sidebar (SMDA export via smda.binja)
│   ├── ghidra/              # Ghidra backend, SMDA export, Swing UI (ui/), Java bridge (java/),
│   │                        # entry script (ghidra_scripts/MCRIT.py)
│   └── headless/            # backend without a disassembler: SMDA disassembles the file itself
├── scripts/
│   ├── common/              # shared checks, fixtures, headless integration runner
│   ├── ida/                 # IDA packaging, metadata sync, integration runners
│   ├── binja/               # Binary Ninja metadata sync, integration runner
│   └── ghidra/              # Ghidra extension packaging, PyGhidra headless and GUI runners
├── tests/
│   ├── core/                # pytest: core and headless backend
│   ├── ui_qt/               # pytest: McritSession; sorted tables with PySide6
│   ├── ida/                 # pytest for the IDA entry point, backend, release guard; in-IDA tests
│   ├── binja/               # pytest for the Binja token storage; in-Binary Ninja integration tests
│   └── ghidra/              # pytest for the Ghidra frontend's JVM-free logic
└── .github/workflows/
    └── scripts/ida/release_guard.py   # tag, version and changelog gates for the IDA release
```

Everything that touches a disassembler goes through `mcrit_plugin/core/Backend.py`.

## Checks

```bash
python scripts/common/verify_settings_sync.py --repo .
python scripts/common/run_quality_checks.py --repo .   # ruff format + ruff check
python -m pytest tests
actionlint

python scripts/ida/verify_metadata_sync.py --repo .
python scripts/ida/package_plugin.py --repo . --output dist/mcrit-ida.zip
hcli plugin lint dist/mcrit-ida.zip

python scripts/binja/verify_metadata_sync.py --repo .

python scripts/ghidra/package_extension.py --repo . --output dist/mcrit-ghidra.zip
```

| Workflow | Name in Actions | Runs on | What |
|---|---|---|---|
| `pytest.yml` | pytest | push, PR, dispatch | pytest, headless integration against MCRIT |
| `ruff.yml` | Validate | push, PR, dispatch | ruff, settings sync, actionlint |
| `changelog.yml` | Changelog | PR | changelog entry for changes shipped in either plugin |
| `ida-package.yml` | IDA package | push, PR touching that plugin | metadata sync and package validation |
| `binja-package.yml` | Binary Ninja package | push, PR touching that plugin | metadata sync and package validation |
| `ghidra-tests.yml` | Ghidra CI | push, PR touching that plugin, dispatch | headless and GUI integration against MCRIT |
| `ida-tests.yml` | IDA CI | push to main or PR touching that plugin, dispatch | licensed IDA 9.0–9.5 headless and GUI integration |
| `binja-tests.yml` | Binary Ninja CI | push, PR touching that plugin, dispatch | licensed headless and GUI integration |
| `ida-release.yml` | IDA release | `ida-v*` tag | release, see [RELEASING.md](../RELEASING.md) |
| `binja-release.yml` | Binary Ninja release | dispatch | release, see [RELEASING.md](../RELEASING.md) |
| `offline-dependencies.yml` | Offline dependencies | called by release workflows, or dispatch | Windows wheelhouse bundles |

"Touching that plugin" means a change to one of these paths:

- IDA: `mcrit_plugin/ida/`, `scripts/ida/`, `tests/ida/`, `.github/workflows/ida-*.yml`,
  `.github/workflows/scripts/ida/`, `CHANGELOG.md`, `docs/config_override.json.template`
- Binary Ninja: `mcrit_plugin/binja/`, `plugin.json`, `__init__.py`, `requirements.txt`,
  `scripts/binja/`, `tests/binja/`, `.github/workflows/binja-*.yml`, and `**/ida-plugin.json`,
  because the archive check has to prove that file is still `export-ignore`d
- Ghidra: `mcrit_plugin/ghidra/`, `scripts/ghidra/`, `tests/ghidra/`,
  `.github/workflows/ghidra-*.yml`, plus the shared core, `McritSession.py`, `icons/`,
  `scripts/common/` and `tests/fixtures/`
- both: `mcrit_plugin/__init__.py`, `mcrit_plugin/core/`, `mcrit_plugin/ui_qt/`, `icons/`,
  `scripts/common/`, `tests/core/`, `tests/ui_qt/`, `tests/conftest.py`, `tests/fixtures/`,
  `README.md`, `LICENSE`, `pyproject.toml`, `.gitattributes`

So a Binary Ninja-only change does not start the IDA jobs and the other way round. A workflow
skipped by its path filter reports no status, so do not make those checks required in branch
protection.

## Integration tests

All integration tests except the offline modes need a MCRIT server. CI uses MCRIT 1.12.0 and
SMDA 4.10.0. Every runner refuses to start while the plugin it runs has a `config_override.json`,
which would take precedence over the settings under test.

```bash
docker run --rm -p 27017:27017 mongo:5.0
python3.12 -m venv .venv-mcrit
.venv-mcrit/bin/python -m pip install "mcrit==1.12.0"
.venv-mcrit/bin/python -m mcrit server
.venv-mcrit/bin/python -m mcrit worker
```

Build the fixtures and seed the reference variant so the query has something to match:

```bash
python scripts/common/build_test_fixture.py --source tests/fixtures/mcrit_sample.c --output /tmp/mcrit-reference --variant 0
python scripts/common/build_test_fixture.py --source tests/fixtures/mcrit_sample.c --output /tmp/mcrit-query --variant 1
.venv-mcrit/bin/python scripts/common/seed_mcrit.py --server http://127.0.0.1:8000 --sample /tmp/mcrit-reference
```

Pass the reference sample's SHA-256 as `--reference-sha256` to also assert that the query matches it.

### Headless (no licence)

Drives conversion, upload, matching and label import through the headless backend. CI runs it on
every push and pull request.

```bash
python scripts/common/run_headless_integration.py --input /tmp/mcrit-query --reference-sha256 <sha256>
```

### IDA

`.github/workflows/ida-tests.yml` runs the live suite on Linux for every minor version from 9.0
through 9.5, on pushes to `main`, on pull requests from a branch of this repository, and on manual
dispatch, using the `IDA_LICENSE_ID` and `HCLI_API_KEY` secrets. Qt 5 is installed for 9.0 and 9.1;
later versions use the installer's PySide6. Pushes to `main` and manual runs also check IDALib on
IDA 9.5 for Windows and macOS ARM, without an MCRIT server or the GUI. Pull requests from a fork, and
repositories without those secrets, cannot run the licensed jobs. They are then skipped, and the
"Integration result" check passes with a warning that names the reason, so a skipped licensed job
never reads as a tested one; a failure in any job that did run fails it. Logs are kept for 14
days; licence files and user profiles are not uploaded.

IDALib covers packaging, conversion, upload and matching without a GUI. Use the Python version
your IDA is configured for, and install `idapro` from that IDA:

```bash
python3 -m venv .venv-idalib
.venv-idalib/bin/python -m pip install "/path/to/IDA Professional 9.3/idalib/python"/idapro-*.whl \
  "smda==4.10.0" "ida-settings==3.5.1" "PySide6" "requests"
.venv-idalib/bin/python scripts/ida/run_idalib_integration.py \
  --ida-dir "/path/to/IDA Professional 9.3" --input /tmp/mcrit-query \
  --idausr /tmp/mcrit-idalib-user --mcrit-server http://127.0.0.1:8000
```

The GUI test also exercises the widgets, dialogs, YARA builder, labels, graphs and SMDA export:

```bash
python scripts/ida/run_gui_integration.py \
  --ida-dir "/path/to/IDA Professional 9.3.app" --input /tmp/mcrit-query \
  --mcrit-server http://127.0.0.1:8000
```

- Without `--idausr` it uses your normal IDA profile. It points that profile at the given server,
  replaces the installed plugin with the local build, and restores `ida-config.json` afterwards.
  If the profile has no `cfg/idapython.cfg`, it creates one that sets
  `IDAPYTHON_USE_PYQT5_SHIM = 0` and leaves it in place. `--plugin-root` tests an already
  installed copy instead of the local ZIP.
- `--offline` skips the MCRIT parts, in both the IDALib and the GUI test.
- IDA still checks its licence on start. If it reports that Python is not configured, run
  `idapyswitch --auto-apply` from that installation.

### Binary Ninja

`binja-tests.yml` uses a full Linux x64 GUI distribution and a Commercial or Ultimate license
that supports headless processing. Configure repository Actions secrets `BN_LICENSE_B64`
(base64-encoded `license.dat`) and `BN_DOWNLOAD_URL_LINUX_X64_STABLE` (the licensed Linux GUI ZIP
URL). A headless-only distribution cannot run the GUI stage. Missing secrets and fork pull
requests explicitly skip integration; package validation and unit tests still run. Credentials
are never cached or uploaded. The workflow uses GitHub-hosted runners only. The GUI explicitly loads the same Python shared
library that installed its dependencies, and imports Binary Ninja's own Qt bindings.

For local runs, use a licensed Binary Ninja and a Python environment matching its interpreter, with
`smda>=4.9.0` (it provides `smda.binja`) and `requests` installed. The runner uses a throwaway user
directory with this checkout linked as a plugin, so your own profile isn't touched. The query file
must have a SHA-256 the server hasn't seen yet.

```bash
python scripts/binja/run_headless_integration.py --input /tmp/mcrit-query \
  --reference-sha256 <sha256> --mcrit-server http://127.0.0.1:8000/ --license /path/to/license.dat
python scripts/binja/run_gui_integration.py --input /tmp/mcrit-query \
  --reference-sha256 <sha256> --mcrit-server http://127.0.0.1:8000/
```

### Exporter agreement

MCRIT matches on normalized instructions, so IDA, Binary Ninja and SMDA should produce the same
PicHashes for the same binary:

```bash
python scripts/common/compare_smda_reports.py \
  --report ida=ida.smda --report binja=binja.smda --binary sample.exe --min-agreement 0.9
```

The script pairs functions by address. Ghidra maps a position-independent ELF at 0x100000 where IDA
and SMDA use 0, so compare a Ghidra export of such a file through
`scripts/ghidra/run_pyghidra_integration.py`, which pairs them relative to the image base.


### Ghidra

No licence is needed, so `ghidra-tests.yml` runs both tests on every change to the Ghidra plugin.
Use Ghidra 12.0 or newer on the JDK it asks for (21 up to 12.1, 25 from 12.2), and a Python with
PyGhidra from that Ghidra, `smda>=4.9.0` and `requests`; `GHIDRA_INSTALL_DIR` points at the
installation.

```bash
python -m pip install --no-index -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
python -m pip install "smda==4.10.0" requests
```

The headless run imports the input into a throwaway project, compares Ghidra's export with SMDA's
own disassembly (PicHash agreement), and drives upload, matching, a function query and label import
through `GhidraBackend`. `--offline` stops after the comparison.

```bash
python scripts/ghidra/run_pyghidra_integration.py --input /tmp/mcrit-query --reference-sha256 <sha256>
```

The GUI run starts Ghidra in PyGhidra mode with a throwaway profile and project, opens MCRIT through
`mcrit_plugin/ghidra/ghidra_scripts/MCRIT.py` and works through every tab and dialog, the remote
CFG, export, switching programs and the upload prompt on close. The input must be new to the server. It needs a display;
`--screenshots DIR` keeps one per step (through ImageMagick's `import` where it is installed, else
each window paints itself, which also works on macOS). On a screen so narrow that the MCRIT window
shows a single tab header, add `--no-tab-click`: the run then selects the tab directly instead of
pressing the mouse on it.

```bash
python scripts/common/build_test_fixture.py --source tests/fixtures/mcrit_sample.c --output /tmp/mcrit-gui-query --variant 2
xvfb-run -a -s "-screen 0 1600x1000x24" python scripts/ghidra/run_gui_integration.py \
  --input /tmp/mcrit-gui-query --reference-sha256 <sha256> --screenshots /tmp/mcrit-ghidra-shots
```

PyGhidra unloads the modules a script imported once the script ends. `MCRIT.py` keeps them for its
own run (`pyghidra.sys.modules.restore.disable`): SMDA's dependency LIEF aborts the process when
it is loaded a second time. The window's state lives on `sys`, so running the script again finds it.

## Releases

See [RELEASING.md](../RELEASING.md) and [CHANGELOG.md](../CHANGELOG.md).

## Workflow maintenance

External actions are pinned to full commit SHAs and updated by Dependabot. Tokens default to
`contents: read`; only the jobs that publish a release or attach assets to one get write access.
CI runs on branch pushes, not tag pushes, so pushing a release tag starts no second CI run. A
release is checked against the newest CI runs on its exact commit, so after a change that the
path filters skip, dispatch the missing workflow on `main` before releasing. Never use
`pull_request_target` to run pull-request code with licence secrets.

These choices follow GitHub's [secure use guidance](https://docs.github.com/en/actions/reference/security/secure-use),
[concurrency guidance](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
and [immutable release guidance](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
