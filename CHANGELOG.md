# Changelog

All notable changes to casket are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-20

### Added
- **Alpine APK CVE extraction** (PR #33, `_parse_apk_installed` in `casket/checks/cves.py`): CVE coverage for `python:*-alpine`, `nginx:alpine`, distroless Alpine — reads `/lib/apk/db/installed` and resolves via OSV `Alpine:edge` ecosystem.
- **SARIF 2.1.0 output format** (PR #36 + earlier rotation, `_render_sarif` in `casket/findings.py`): emits OASIS SARIF 2.1.0 with severity → level mapping (`critical/high → error`, `medium → warning`, `low/info → note`). Drop-in for GitHub Code Scanning. Tested by `tests/test_sarif.py` (11 structural tests) + E2E in `tests/test_cli_e2e.py`.
- **RPM SQLite CVE extraction** (PR #34, `_parse_rpmdb_sqlite` in `casket/checks/cves.py`): CVE coverage for RHEL 9+ / Fedora / Amazon Linux 2023 — opens `var/lib/rpm/rpmdb.sqlite` with stdlib `sqlite3`, decodes RPM header blobs, composes `epoch:version-release` EVR strings, resolves via OSV `Red Hat` ecosystem. Legacy BDB `Packages` is skipped silently.
- **Registry bearer-token authentication** (PR #35 + earlier, `remote_mode.py`): OCI Distribution Spec `WWW-Authenticate: Bearer realm=...` challenge-response flow. New flags `--token`, `--registry-user`, `--registry-password` plus `CASKET_REGISTRY_USER` / `CASKET_REGISTRY_PASSWORD` env vars. Zero new deps (httpx already present).
- **Expanded credential ruleset** (PR #37, `creds.yaml`): added Azure, OpenAI, Anthropic, Databricks, and Vault token patterns (5 new rules, 9 total).
- **`--only-actionable` filter** (PR #36, `casket/report.py`): report-only CVE findings that have a vendor fix.
- **`--purl-filter` flag** (PR #35, `casket/cli.py`): package-level CVE selection by PURL substring.
- **`--cvss-floor` flag** (PR #34, `casket/cli.py`): numeric CVSS base-score filter.
- **`--diff-format h1md` flag** (PR #32, `casket/report.py`): human-readable `--compare` output.
- **Wheel ship-gate** (PR #39, `tests/test_wheel_ship_gate.py`): 7 `@pytest.mark.ship_gate` tests pin the v1.0 wheel-install contract (build wheel + sdist, fresh-venv install, `--version` from fresh venv, `__version__` import, all 12 public modules import, registry smoke, `--help` exits 0, all `--checks` categories validate).

### Changed
- **`[dev]` extra fix** (PR #38, `pyproject.toml`): added `httpx>=0.27` and `pyyaml>=6.0` so `pip install -e ".[dev]"` is sufficient for `pytest -q` (previously required a separate `pip install httpx pyyaml`).
- **`build>=1.0` in `[dev]` extras** (PR #39): ensures `python -m build` works from `pip install -e ".[dev]"` for the ship-gate test.

### Fixed
- **`tests/test_install_sanity.py`**: version assertion now follows `__version__` (was hardcoded to `"0.1.0"`; this release flips to `"1.0.0"`).
- **`tests/test_wheel_ship_gate.py`**: `EXPECTED_VERSION` now follows the release-cut (was hardcoded to `"0.1.0"`; this release flips to `"1.0.0"`).

### Notes
- No new runtime dependencies (httpx was already a runtime dep).
- No breaking CLI changes since v0.1 (new flags are additive only).
- 580 tests passing at v1.0.0 (579 baseline + 1 new CHANGELOG ship_gate test).
- 100% of `casket --version` and `import casket; casket.__version__` paths verified at HEAD.
- This is the first v1.0 production-ready release of casket.

[1.0.0]: https://github.com/bugsyhewitt/casket/releases/tag/v1.0.0
