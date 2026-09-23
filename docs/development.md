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
│   ├── binja/               # Binary Ninja backend, SMDA exporter interface, settings, sidebar
│   └── headless/            # backend without a disassembler: SMDA disassembles the file itself
├── scripts/
│   ├── common/              # shared checks, fixtures, headless integration runner
│   ├── ida/                 # IDA packaging, metadata sync, integration runners
│   └── binja/               # Binary Ninja metadata sync, integration runner
├── tests/
│   ├── core/                # pytest suite
│   ├── ida/                 # in-IDA integration tests
│   └── binja/               # in-Binary Ninja integration tests
└── .github/workflows/
    └── scripts/ida/release_guard.py   # tag, version and changelog gates for the IDA release
```

Everything that touches a disassembler goes through `mcrit_plugin/core/Backend.py`.

## Checks

```bash
python scripts/common/verify_settings_sync.py --repo .
python scripts/common/run_quality_checks.py --repo .   # ruff format + ruff check
python -m pytest tests

python scripts/ida/verify_metadata_sync.py --repo .
python scripts/ida/package_plugin.py --repo . --output dist/mcrit-ida.zip
hcli plugin lint dist/mcrit-ida.zip

python scripts/binja/verify_metadata_sync.py --repo .
```

| Workflow | Name in Actions | Runs on | What |
|---|---|---|---|
| `pytest.yml` | pytest | push, PR | pytest, headless integration against MCRIT |
| `ruff.yml` | Validate | push, PR | ruff, settings sync |
| `changelog.yml` | Changelog | PR | changelog entry for changes shipped in either plugin |
| `ida-package.yml` | IDA package | push, PR touching that plugin | metadata sync and package validation |
| `binja-package.yml` | Binary Ninja package | push, PR touching that plugin | metadata sync and package validation |
| `ida-tests.yml` | IDA integration | push to main or PR touching the IDA plugin, dispatch | licensed IDA integration |
| `ida-release.yml` | IDA release | `ida-v*` tag | release, see [RELEASING.md](../RELEASING.md) |
| `binja-release.yml` | Binary Ninja release | dispatch | release, see [RELEASING.md](../RELEASING.md) |
| `offline-dependencies.yml` | Offline dependencies | called by both releases, or dispatch | Windows wheelhouse bundles |

"Touching that plugin" means a change to one of these paths:

- IDA: `mcrit_plugin/ida/`, `scripts/ida/`, `tests/ida/`, `.github/workflows/ida-*.yml`,
  `.github/workflows/scripts/ida/`, `CHANGELOG.md`, `docs/config_override.json.template`
- Binary Ninja: `mcrit_plugin/binja/`, `plugin.json`, `__init__.py`, `requirements.txt`,
  `scripts/binja/`, `tests/binja/`, `.github/workflows/binja-*.yml`, and `**/ida-plugin.json`,
  because the archive check has to prove that file is still `export-ignore`d
- both: `mcrit_plugin/core/`, `mcrit_plugin/ui_qt/`, `icons/`, `scripts/common/`, `tests/core/`,
  `tests/conftest.py`, `tests/fixtures/`, `README.md`, `LICENSE`, `pyproject.toml`, `.gitattributes`

So a Binary Ninja-only change does not start the IDA jobs and the other way round. A workflow
skipped by its path filter reports no status, so do not make those checks required in branch
protection.

## Integration tests

All integration tests except the offline modes need a MCRIT server. CI uses MCRIT 1.9.0 and
SMDA 4.8.0.

```bash
docker run --rm -p 27017:27017 mongo:5.0
python3.12 -m venv .venv-mcrit
.venv-mcrit/bin/python -m pip install "mcrit==1.9.0"
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

`.github/workflows/ida-tests.yml` runs these on pushes to `main`, on pull requests from a branch of
this repository, and on manual dispatch, using the `IDA_LICENSE_ID` and `HCLI_API_KEY` secrets. Pull
requests from a fork, and repositories without those secrets, cannot run the licensed job. It is
then skipped, and the "Licensed IDA result" check passes with a warning that names the reason, so a
skipped licensed job never reads as a tested one. Dispatch the workflow on a branch of this
repository to get the signal. Dispatch with `run_matrix` for more IDA versions and platforms.

IDALib covers packaging, conversion, upload and matching without a GUI. Use the Python version
your IDA is configured for, and install `idapro` from that IDA:

```bash
python3 -m venv .venv-idalib
.venv-idalib/bin/python -m pip install "/path/to/IDA Professional 9.3/idalib/python"/idapro-*.whl \
  "smda==4.8.0" "ida-settings==3.5.1" "PySide6" "requests"
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

- Without `--idausr` it uses your normal IDA profile. It points that profile at the given server
  and restores `ida-config.json` afterwards. `--plugin-root` tests an already installed copy
  instead of the local ZIP.
- `--offline` skips the MCRIT parts, in both the IDALib and the GUI test.
- IDA still checks its licence on start. If it reports that Python is not configured, run
  `idapyswitch --auto-apply` from that installation.

### Binary Ninja

Needs a licensed Binary Ninja and a Python environment matching its interpreter, with `smda` and
`requests` installed. The runner uses a throwaway user directory with this checkout linked as a
plugin, so your own profile isn't touched. The query file must have a SHA-256 the server hasn't
seen yet.

```bash
python scripts/binja/run_gui_integration.py --input /tmp/mcrit-query.exe \
  --reference-sha256 <sha256> --mcrit-server http://127.0.0.1:8000/
```

### Exporter agreement

MCRIT matches on normalized instructions, so IDA, Binary Ninja and SMDA should produce the same
PicHashes for the same binary:

```bash
python scripts/common/compare_smda_reports.py \
  --report ida=ida.smda --report binja=binja.smda --binary sample.exe --min-agreement 0.9
```

## Releases

See [RELEASING.md](../RELEASING.md) and [CHANGELOG.md](../CHANGELOG.md).
