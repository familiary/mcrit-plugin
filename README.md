# MCRIT Plugin

[![IDA Version](https://img.shields.io/badge/IDA-9.0%2B-blue.svg)](https://hex-rays.com/ida-pro/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)
[![HCLI Compatible](https://img.shields.io/badge/HCLI-compatible-brightgreen.svg)](https://hcli.docs.hex-rays.com/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/danielplohmann/mcrit-plugin)

Client for [MCRIT](https://github.com/danielplohmann/mcrit), the MinHash-based code similarity server, for IDA Pro and Binary Ninja. It exports your database as an SMDA report, uploads it, and shows matching blocks, functions and labels from the server next to your analysis.

- Block and function matches for the current cursor position
- Function overview with label import and conflict resolution
- Matching jobs against the whole server or a sample group
- YARA string builder from a selection
- CFG view of remote matched functions

## IDA Pro

Requires IDA 9.0 or newer.

### Install with HCLI

```bash
python -m pip install --upgrade ida-hcli
hcli plugin install mcrit-ida
```

`hcli plugin upgrade mcrit-ida` and `hcli plugin uninstall mcrit-ida` work as usual. To install a local build instead:

```bash
python scripts/ida/package_plugin.py --repo . --output ../mcrit-ida.zip
hcli plugin install ../mcrit-ida.zip
```

In CI or a headless shell, pass settings with `--config mcrit_server=https://mcrit.example.com/api/` (and `mcritweb_api_token`, `mcritweb_username`, `mcrit_request_timeout`) so `hcli` doesn't prompt.

### Install manually

1. Extract a release ZIP into `$IDAUSR/plugins/mcrit-ida/`. A repository checkout won't work directly: the packager puts `ida-plugin.json` and `ida_mcrit.py` at the archive root.
2. Install the dependencies with IDA's Python: `python -m pip install "smda>=4.3.10" "ida-settings>=3.5.1" requests`
3. Restart IDA.

IDA 9.4 may ask once whether to enable PyQt5 shims when the plugin loads; answer No. The prompt comes from the `ida-settings` dependency, and the plugin itself uses PySide6.

For offline machines, each release has a wheelhouse bundle: unpack it and run `python -m pip install --no-index --find-links=. -r requirements.txt`.

### Configure

Settings are handled by [ida-settings](https://github.com/williballenthin/ida-settings):

- HCLI: `hcli plugin config mcrit-ida set mcrit_server https://mcrit.example.com/api/` (`list`, `get`, `export` and `import` also work)
- GUI: install `ida-settings-editor` and use Edit → Plugins → Plugin Settings Manager
- File: put a `config_override.json` next to `ida_mcrit.py` (template in `docs/config_override.json.template`)

### Use

1. Open a binary and start MCRIT4IDA from Edit → Plugins, or press Ctrl-F4.
2. Use the toolbar to convert the database to an SMDA report, upload it, and fetch a matching result.
3. Browse the results in the Block Scope, Function Scope, Function Overview and Sample Match Summary tabs.

## Binary Ninja

Requires Binary Ninja 6.0 (build 10601) or newer.

### Install

Install MCRIT from the Extension Manager, or clone this repository into your Binary Ninja user plugins folder and install `requirements.txt` into Binary Ninja's Python. For offline machines, each release has a `binja` wheelhouse bundle. It is built for Windows only, and is installed the same way as the IDA bundle.

### Configure

Settings are under Settings → MCRIT, with the same keys as the IDA plugin. Where a system keychain is available, an API token entered there is moved into it and the field is cleared; otherwise the token stays in the Settings entry. Plugins → MCRIT → Clear Stored API Token removes it.

### Use

Open the MCRIT sidebar, or run any MCRIT action from the command palette or Plugins → MCRIT. It has the same toolbar and tabs as the IDA plugin. Reports are exported from Binary Ninja's own analysis, and remote CFGs open as graph reports.

## Settings

The keys below are the ones most often changed; `mcrit_plugin/core/settings.json` declares all of
them, with their types and defaults.

| Setting | Description | Example |
| :--- | :--- | :--- |
| `mcrit_server` | Server URL | `https://mcrit.example.com/api/` |
| `mcritweb_api_token` | MCRITweb API token; the username is inferred from it | `eyJ0eXAi...` |
| `mcritweb_username` | Username (optional) | `analyst` |
| `mcrit_request_timeout` | Request timeout in seconds | `10` |
| `sample_group_only` | Restrict matching to the server-side sample group | `false` |

## Development

See [docs/development.md](docs/development.md) for the layout, checks, integration tests and release process.

## Version History

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

## License

GPL-3.0, see [LICENSE](LICENSE).

## Authors

- Daniel Plohmann ([@danielplohmann](https://github.com/danielplohmann))
- Rony ([@r0ny123](https://github.com/r0ny123))
