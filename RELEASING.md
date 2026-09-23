# Releasing the MCRIT plugins

This repository follows the release process shared across the MCRIT ecosystem
([smda](https://github.com/danielplohmann/smda), [purepdb](https://github.com/danielplohmann/purepdb),
[mcrit](https://github.com/danielplohmann/mcrit), [mcritweb](https://github.com/fkie-cad/mcritweb),
[mcrit-plugin](https://github.com/danielplohmann/mcrit-plugin),
[docker-mcrit](https://github.com/danielplohmann/docker-mcrit)). The shape is the same everywhere;
this file states the values that are specific to this repository.

This repository ships two plugins that are versioned and released independently: the IDA plugin
follows the shared process below, and the Binary Ninja plugin is released through the extension
manager's own workflow ([Binary Ninja](#binary-ninja)).

## IDA

### Versioning

The plugin follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) over what a user
sees: the settings declared in `ida-plugin.json`, the minimum IDA version, the Python packages
the plugin needs in IDA's interpreter, and how the plugin is installed. That last one is why 2.0.0
is a major release although no setting, version floor or dependency changed: copying a repository
checkout into the plugins directory was a documented install method and no longer works. It is
distributed as a ZIP for
[HCLI](https://docs.hex-rays.com/user-guide/plugins/hcli) and attached to the GitHub release, not
published to PyPI.

The version is declared in `mcrit_plugin/ida/ida-plugin.json` (`plugin.version`) and
`mcrit_plugin/ida/config.py` (`VERSION`); `verify_metadata_sync.py` also
requires the newest release heading in `CHANGELOG.md` — the topmost one below `## [Unreleased]` — to
agree. The release workflow refuses a tag that does not
match every one of them, so a bump that misses one fails before anything is published.

### Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and is the
authoritative record of what a release contains for both plugins: the GitHub release notes are
generated from it. Add an entry when the change merges, while the reasoning is still at hand, rather
than reconstructing it from the commit log at release time.

- Every pull request that changes something a user can observe adds its own bullet under
  `## [Unreleased]`, in the subsection it belongs to (`Added`, `Changed`, `Deprecated`, `Removed`,
  `Fixed`, `Security`), while the change is fresh. The `Changelog` check fails a PR that touches
  files shipped in either plugin (`mcrit_plugin/core`, `mcrit_plugin/ui_qt`, `mcrit_plugin/ida`,
  `mcrit_plugin/binja`, `icons`) without touching `CHANGELOG.md`; apply the `no-changelog` label when a change
  genuinely needs no entry (a typo, a CI-only change), and say why in the PR.
- An entry says what changed and what it costs the reader: what to do when upgrading, what may
  behave differently, which issue or PR it closes.
- Dependency bumps need no entry. GitHub lists them under their own heading in the release notes,
  from the `dependencies` / `github_actions` labels (`.github/release.yml`).

### Cutting a release

1. Check that `main` is green and that everything meant for the release has merged.
2. In one commit on a branch, then merged through a PR:
   - set the new version in `mcrit_plugin/ida/ida-plugin.json` (`plugin.version`) and
     `mcrit_plugin/ida/config.py` (`VERSION`);
   - in `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, drop the empty
     subsections, open a fresh empty `## [Unreleased]` above it, and update the compare link at
     the foot of the file.
3. Wait for CI to pass on the merge commit. Then tag that commit and push the tag:

   ```bash
   git tag -a ida-vX.Y.Z -m "the MCRIT IDA plugin X.Y.Z"
   git push origin ida-vX.Y.Z
   ```

Pushing the tag is the release. `.github/workflows/ida-release.yml` then:

1. **Verify** — refuses to continue unless the tag matches both version strings, `CHANGELOG.md` has a
   `## [X.Y.Z] - <date>` section (which becomes the release notes), the tagged commit is on `main`,
   and the `pytest` workflow passed on that commit.
2. **Validate and build** — runs `verify_metadata_sync.py` against the tag's version,
   `verify_settings_sync.py` and `run_quality_checks.py`, builds `mcrit-ida-<version>.zip`, and lints
   the archive with `hcli plugin lint`.
3. **Release** — creates the GitHub release for the tag with the changelog section as its body,
   GitHub's generated contributor and PR list appended under it, and the archive attached. It is
   never marked as the latest release, because the Binary Ninja extension manager reads the latest
   release.
4. **Offline dependencies** — calls `offline-dependencies.yml`, which attaches the Windows
   wheelhouse bundles (`smda` and `full`) to the release. It is called directly because a release
   created with `GITHUB_TOKEN` does not start workflows that listen for release events. To attach
   bundles to an existing release, run it by hand with that release's tag.

Each gate fails with a message naming what to fix. Nothing has to be remembered at the console.

### Pre-releases

A release candidate is tagged `ida-vX.Y.Zrc1` (also `a1`, `b1`), with the same version string in
`ida-plugin.json` and `config.py`, and a `## [X.Y.Zrc1] - YYYY-MM-DD` changelog section. The workflow
marks the GitHub release as a pre-release.

### Rehearsing

There is no index to rehearse against. The gates and the build run on every tag before the release
is created, and a tag that fails a gate leaves nothing behind; delete it, fix the cause, and tag
again. The same checks run locally:

```bash
python scripts/ida/verify_metadata_sync.py --repo . --expected-version X.Y.Z
python scripts/common/verify_settings_sync.py --repo .
python scripts/common/run_quality_checks.py --repo .
python scripts/ida/package_plugin.py --repo . --output dist/mcrit-ida-X.Y.Z.zip
hcli plugin lint dist/mcrit-ida-X.Y.Z.zip
```

### When a release fails

- **A gate failed before anything was published** (tag/version mismatch, missing changelog section,
  tag not on `main`, CI not green): fix the cause on `main`, delete the
  tag locally and on the remote (`git push --delete origin ida-vX.Y.Z`), and tag again once the fix has
  merged. Nothing needs cleaning up.

- **A job failed at or after the release step**: `gh release create` is not idempotent, so start by
  checking what exists (`gh release view ida-vX.Y.Z`).
  - The release exists and is correct: re-run only the jobs that failed after it; the built
    artifacts are kept as workflow artifacts.
  - The release was never created: fix the cause and re-run the failed job.
  - The release exists but is wrong: delete it and the tag
    (`gh release delete ida-vX.Y.Z --cleanup-tag`), fix the cause, and tag again.

### Maintainer configuration

Done once, by a repository owner; the workflow cannot create these for itself.

- **Label** `no-changelog`, used by the changelog check.
- Optionally, **immutable releases** (Settings → General → Releases), so a published release's
  assets and tag can no longer be changed. Note that the offline-dependency workflow uploads
  assets to the release after it is published, so it has to finish before a release is made
  immutable.

### Release order across the ecosystem

The plugin vendors a minimal MCRIT client (`mcrit_plugin/core/minimcrit/`) rather than importing the `mcrit`
package, so it is not released in lockstep with MCRIT; it talks to the server over the REST API.
It does need `smda` in the disassembler's interpreter (`pythonDependencies` in `ida-plugin.json`,
`requirements.txt` for Binary Ninja), so when a
change here needs a newer smda, release smda first and raise the floor there.

## Binary Ninja

The Binary Ninja plugin follows the same Semantic Versioning scope as the IDA plugin, read against
what Binary Ninja exposes: the settings registered under Settings → MCRIT, the minimum Binary Ninja
build, and `requirements.txt`. Its version lives only in the root `plugin.json`. [extensions.binary.ninja](https://extensions.binary.ninja)
reads `plugin.json` from the commit of the latest GitHub release and compares nothing but its
`version`: tag names and release titles are never parsed, and a version it has already seen is
silently skipped.

Releases are started by hand, from Actions → Binary Ninja release → Run workflow, or:

```bash
gh workflow run binja-release.yml -f dry-run=true
gh workflow run binja-release.yml -f version=1.1.0   # blank bumps the last number
```

`.github/workflows/binja-release.yml` checks that CI passed on `main`, runs the metadata, settings,
quality and pytest checks there with a read-only token, then hands the same commit to [Vector35/plugin_actions](https://github.com/Vector35/plugin_actions),
the release action of Vector35's sample plugin. It bumps `plugin.json`, commits it as
`github-actions[bot]`, tags the commit with the bare version and publishes it as the latest GitHub
release. If `main` moved between the checks and the release, the run stops. Afterwards it calls
`offline-dependencies.yml` to attach a `binja` wheelhouse bundle built from `requirements.txt`.

`binja-package.yml`, the counterpart of `ida-package.yml`, runs on pushes and pull requests that
touch the Binary Ninja plugin or anything both plugins share (see
[docs/development.md](docs/development.md)). It checks
that `plugin.json`, `requirements.txt` and the README agree and that the source archive has the
plugin at its root without `ida-plugin.json`, then validates `plugin.json` with a dry run of the
same release action.

- If `main` is protected, `github-actions[bot]` must be allowed to push.
- Versions `1.1.4`, `1.1.5`, `1.1.7`–`1.1.9` and `1.4.5` cannot be used: earlier tags already name
  them, and the action refuses to reuse a version a tag already names.
- After the first release, open an issue on
  [Vector35/community-plugins](https://github.com/Vector35/community-plugins/issues/new/choose) to get
  the plugin listed.
