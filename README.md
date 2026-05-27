# casket

**A daemonless, podman-native container image scanner. No Docker, no daemon, no root.**

`casket` inspects container images for three classes of problems and tells you
*which layer* introduced each one:

- **leaked credentials** — AWS keys, API tokens, private keys planted in a layer
- **known-vulnerable packages** — PyPI, Debian, and Alpine packages resolved
  against [OSV.dev](https://osv.dev)
- **misconfigurations** — `USER root`, exposed ports, secret-like env vars

It reads images three ways:

| mode | input | needs |
|---|---|---|
| `tarball` | an OCI image tarball / `docker save` / `podman save` archive | nothing |
| `podman` | a local podman image reference | the `podman` CLI |
| `remote` | a registry URL (OCI distribution API) | network access |

`casket` never talks to a Docker daemon and never needs root. It parses the
[OCI Image Layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
directly with the Python standard library.

## Why daemonless

The 2026 container landscape moved on from the Docker daemon: Podman holds
meaningful market share, daemonless is the security default, and Docker requires
licensing for larger organizations. `casket` defends that niche — it works on
image *artifacts* and the `podman` socket/CLI, so it runs in CI, in a locked-down
container, or on a laptop with no privileged daemon at all.

## Install

```bash
git clone https://github.com/bugsyhewitt/casket
cd casket
pip install -e .        # Python 3.13+
```

This installs the `casket` console command.

## System dependencies

- **Python 3.13+** (required)
- **`podman` CLI** — *optional but recommended.* Only needed for `--mode podman`.
  Install it from your distro (`apt install podman`, `dnf install podman`,
  `brew install podman`). If `podman` is absent, `--mode podman` fails with a
  clear message; `tarball` and `remote` modes work without it.
- **Network access** — only needed for `--mode remote` and for live CVE lookups.
  `casket` ships a small bundled OSV seed database and caches every OSV.dev
  result to disk, so repeat scans and offline runs work without hammering the API.

## Usage

```
casket --image REF
       --mode {tarball,podman,remote}
       --checks {creds,cves,misconfig,all}
       --format {json,h1md,sarif}
       [--offline]
```

Exit codes: `0` clean, `1` findings present (handy for CI gates), `2` load error.

### tarball mode (no dependencies)

```bash
casket --image ./myapp.tar --mode tarball --checks all --format json
```

### podman mode (requires the `podman` CLI)

```bash
casket --image localhost/myapp:latest --mode podman --checks creds
```

`casket` shells out to `podman save --format oci-archive` and scans the
resulting OCI archive — daemonless throughout.

### remote mode (requires network)

```bash
casket --image http://registry.internal:5000/team/app:1.2 --mode remote --checks all
```

`casket` pulls the manifest, config, and layer blobs over the OCI distribution
API and scans them in memory.

### output formats

- `--format json` — the canonical machine-readable report. Every finding carries
  `category`, `severity`, `layer_sha`, and `path_in_layer`, plus category-specific
  fields (`rule` for creds/misconfig; `cve_id`, `package`, `installed_version`
  for CVEs).
- `--format h1md` — a HackerOne-style markdown report for human submission.
- `--format sarif` — [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
  for CI/CD code-scanning ingest. Each finding type becomes a `rule` and each
  finding a `result`; severity maps to SARIF levels (CRITICAL/HIGH → `error`,
  MEDIUM → `warning`, LOW/INFO → `note`). Feed it straight to GitHub Advanced
  Security via `github/codeql-action/upload-sarif`.

```bash
casket --image ./myapp.tar --checks all --format sarif > casket.sarif
```

#### example finding (json)

```json
{
  "category": "creds",
  "title": "AWS secret access key",
  "severity": "critical",
  "layer_sha": "sha256:d513fd1c…",
  "path_in_layer": "app/.env",
  "rule": "aws_secret_access_key"
}
```

## How CVE lookups stay polite

The CVE check extracts installed packages (PyPI `dist-info`, Debian
`dpkg/status`, and Alpine `lib/apk/db/installed`) and resolves each
`(ecosystem, name, version)` against OSV.dev.
Results are cached to `~/.cache/casket/osv-cache.json` (override with
`CASKET_OSV_CACHE`). A bundled read-only seed DB resolves a small curated set
with no network at all. Pass `--offline` to forbid network access entirely.

## Development

```bash
pip install -e '.[dev]'
python -m tests.build_fixtures   # regenerate the OCI fixtures (optional)
pytest                            # full suite, no daemon / no network required
```

The fixtures under `tests/fixtures/` are real, hand-rolled OCI image-layout
tarballs built with the standard library — no container runtime needed to make
them. Podman-mode tests mock `subprocess.run`; remote-mode tests run against a
local fixture registry on an ephemeral port.

## Scope (v0.1)

In scope: tarball / podman / remote loading; creds, CVE, and misconfig checks;
per-layer attribution; json, h1md, and sarif output.

**Not in v0.1** (deliberately): Docker daemon support (avoided for security and
licensing), Kubernetes manifest scanning, live cluster scanning, Sigstore
signature verification, SBOM generation, and custom rule DSLs beyond simple YAML.

## Ethical use

`casket` is a defensive security tool. **Only scan images you own or are
explicitly authorized to assess.** Scanning third-party images you do not have
permission to inspect — or using findings to attack systems you do not own — may
be illegal. You are responsible for how you use this tool.

## License

See [LICENSE](LICENSE).
