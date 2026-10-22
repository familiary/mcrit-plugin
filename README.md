# MCRIT Plugin

[![IDA Version](https://img.shields.io/badge/IDA-9.0%2B-blue.svg)](https://hex-rays.com/ida-pro/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)
[![HCLI Compatible](https://img.shields.io/badge/HCLI-compatible-brightgreen.svg)](https://hcli.docs.hex-rays.com/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/familiary/mcrit-plugin)

Client for [MCRIT](https://github.com/familiary/mcrit), the MinHash-based code similarity server, for IDA Pro, Binary Ninja and Ghidra. It exports your database as an SMDA report, uploads it, and shows matching blocks, functions and labels from the server next to your analysis.

- Block and function matches for the current cursor position
- Function overview with label import and conflict resolution
- Matching jobs against the whole server
- YARA string builder from a selection
- CFG view of remote matched functions

## IDA Pro

Requires IDA 9.0 or newer.

### Install with HCLI

```bash
python -m pip install --upgrade ida-hcli
hcli plugin install mcrit-ida
```

`hcli plugin upgrade mcrit-ida` and `hcli plugin uninstall mcrit-ida` work as usual.

Coming from 1.x: `hcli plugin upgrade` does not find 2.0.0, because 1.x was installed from the
repository's old home (`danielplohmann/mcrit-plugin`). Uninstall it, then install again:

```bash
hcli plugin uninstall mcrit-ida
hcli plugin install mcrit-ida
```

To install a local build instead:

```bash
python scripts/ida/package_plugin.py --repo . --output ../mcrit-ida.zip
hcli plugin install ../mcrit-ida.zip
```

In CI or a headless shell, pass settings with `--config mcrit_server=https://mcrit.example.com/api/` (and `mcritweb_api_token`, `mcritweb_username`, `mcrit_request_timeout`) so `hcli` doesn't prompt.

### Install manually

1. Extract a release ZIP into `$IDAUSR/plugins/mcrit-ida/`. A repository checkout won't work directly: the packager puts `ida-plugin.json` and `ida_mcrit.py` at the archive root.
2. Install the dependencies with IDA's Python: `python -m pip install "smda>=4.3.10" "ida-settings>=3.5.1" requests`
3. Restart IDA.

SMDA 4.3.10 is the last release for Python 3.10, so an IDA running Python 3.10, and the release's 3.10 wheelhouse bundle, get that version and none of the SMDA fixes since.

IDA 9.4 may ask once whether to enable PyQt5 shims when the plugin loads; answer No. The prompt comes from the `ida-settings` dependency, and the plugin itself uses PySide6.

For offline machines, each release has a wheelhouse bundle: unpack it and run `python -m pip install --no-index --find-links=. -r requirements.txt`.

### Configure

Settings are handled by [ida-settings](https://github.com/williballenthin/ida-settings):

- HCLI: `hcli plugin config mcrit-ida set mcrit_server https://mcrit.example.com/api/` (`list`, `get`, `export` and `import` also work)
- GUI: the Settings button on the MCRIT toolbar (also Edit → Plugins → MCRIT4IDA Settings...). With `ida-settings-editor` installed it opens the Plugin Settings Manager on mcrit-ida; without it, a small form for the server, API token, username and timeout.
- File: put a `config_override.json` next to `ida_mcrit.py`. Its keys take precedence over the other two, so keep only the ones you want to force; `docs/config_override.json.template` shows the format, and the plugin prints the keys it forces when it loads.

### Use

1. Open a binary and start MCRIT4IDA from Edit → Plugins, or press Ctrl-F4.
2. Use the toolbar to convert the database to an SMDA report, upload it, and fetch a matching result.
3. Browse the results in the Block Scope, Function Scope, Function Overview and Sample Match Summary tabs.
   Opening a match's graph tints the matched blocks of the local function in IDA's disassembly;
   Edit → Plugins → MCRIT4IDA Clear Match Coloring removes the tint.

## Binary Ninja

Requires Binary Ninja 6.0 (build 10601) or newer.

### Install

Install MCRIT from the Extension Manager, or clone this repository into your Binary Ninja user plugins folder and install `requirements.txt` into Binary Ninja's Python. For offline machines, each release has a `binja` wheelhouse bundle. It is built for Windows and Python 3.11 to 3.13 only, and is installed the same way as the IDA bundle.

### Configure

Settings are under Settings → MCRIT, with the same keys as the IDA plugin; the Settings button on the sidebar toolbar and Plugins → MCRIT → Settings open them there. Where a system keychain is available, an API token entered there is moved into it and the field is cleared; otherwise the token stays in the Settings entry. Plugins → MCRIT → Clear Stored API Token removes it. The sidebar reads the connection settings (server, token, username, timeout) when it opens for a file, and again when you close the Settings tab its button opened (a different server only until the sidebar holds results from the current one); after changing them any other way, reopen the file. A `config_override.json` in the plugin's folder, next to `plugin.json`, takes precedence as it does in IDA.

### Use

Open the MCRIT sidebar, or run any MCRIT action from the command palette or Plugins → MCRIT. It has the same toolbar and tabs as the IDA plugin. Reports are exported from Binary Ninja's own analysis, and remote CFGs open as graph reports.

## Ghidra

Requires Ghidra 12.0 or newer, started in PyGhidra mode, on a JDK 21 (Ghidra's own requirement).
The Ghidra plugin is new and has not been released yet; its version is `0.1.0`.

### Install

1. Get this repository: clone it, or download and unpack a source archive. Ghidra runs the plugin
   from there.
2. Start Ghidra in PyGhidra mode: `support/pyghidraRun` (Linux, macOS) or
   `support\pyghidraRun.bat` (Windows). The first start offers to set up PyGhidra in a virtual
   environment in Ghidra's settings folder.
3. Install the dependencies into that environment, e.g. on Linux
   `~/.config/ghidra/ghidra_<version>/venv/bin/python -m pip install "smda>=4.9.0" requests`.
   When they are missing, MCRIT shows the exact command for your installation.
4. In the CodeBrowser, open Window → Script Manager, choose Manage Script Directories and add
   `ghidra_scripts` from this repository.
5. In the Script Manager, find `MCRIT.py` in the MCRIT category and tick its "In Tool" box. This
   adds Tools → MCRIT and the key binding Ctrl+Shift+M; Ghidra creates script menu entries only
   for scripts marked this way.

The first start compiles a small Java class that hosts the MCRIT window, with the JDK Ghidra runs
on, into Ghidra's settings folder. It is rebuilt automatically for a new plugin or Ghidra version.

### Configure

Settings are under Edit → Tool Options → MCRIT: the same settings as in the other plugins, listed by
their display names. The API token field is masked, but Ghidra stores it with the tool's options in
plain text. A `config_override.json` in the repository root takes precedence as it does in IDA.
Settings are read whenever they are used, except the connection settings (server, token, username,
timeout), which are read when MCRIT opens for a program; reopen the program after changing those.

### Use

Run Tools → MCRIT, or the script from the Script Manager. The window docks into the CodeBrowser
with the same toolbar and tabs as the other plugins, one session per open program; it follows the
active program and offers to open MCRIT for a program that has no session yet. Reports are exported
from Ghidra's own analysis, matched local blocks are tinted in the listing (a marker, not saved with
the program; Clear Match Coloring in the MCRIT window's menu removes it), and remote CFGs open in Ghidra's graph view.

## Settings

The keys below are the ones most often changed; `mcrit_plugin/core/settings.json` declares all of
them, with their types and defaults.

| Setting | Description | Example |
| :--- | :--- | :--- |
| `mcrit_server` | Server URL | `https://mcrit.example.com/api/` |
| `mcritweb_api_token` | MCRITweb API token; the username is inferred from it | `eyJ0eXAi...` |
| `mcritweb_username` | Username (optional) | `analyst` |
| `mcrit_request_timeout` | Request timeout in seconds | `10` |

## Development

See [docs/development.md](docs/development.md) for the layout, checks, integration tests and release process.

## Version History

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

## License

GPL-3.0, see [LICENSE](LICENSE).

## Authors

- Daniel Plohmann ([@danielplohmann](https://github.com/danielplohmann))
- Rony ([@r0ny123](https://github.com/r0ny123))
