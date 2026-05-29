# casket

**A daemonless, podman-native container image scanner. No Docker, no daemon, no root.**

`casket` inspects container images for three classes of problems and tells you
*which layer* introduced each one:

- **leaked credentials** — AWS keys, provider tokens (GitHub, Slack, Stripe,
  SendGrid, npm, GCP, Twilio, …), JWTs, private keys, and high-entropy secrets
- **known-vulnerable packages** — PyPI, Debian, Alpine, and RPM (RHEL/Fedora)
  packages resolved against [OSV.dev](https://osv.dev)
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
       [--fail-on {any,critical,high,medium,low,info,none}]
       [--offline]
       [--token TOKEN]
       [--registry-user USER] [--registry-password PASS]
```

Exit codes: `0` clean (or below the `--fail-on` threshold), `1` findings tripped
the gate, `2` load error.

### CI gating with `--fail-on`

By default casket exits `1` if it finds *anything* — a single `INFO` exposed
port breaks the build the same as a leaked AWS key. That's rarely what a
pipeline wants. `--fail-on SEVERITY` sets the gate threshold: casket exits `1`
only when a finding is **at that severity or higher**, while still reporting
*every* finding regardless of threshold.

```bash
# fail the build only on high- or critical-severity findings
casket --image ./myapp.tar --checks all --fail-on high

# never fail on findings — report-only (e.g. publish SARIF without blocking)
casket --image ./myapp.tar --checks all --format sarif --fail-on none > casket.sarif

# original behaviour: fail on any finding (this is the default)
casket --image ./myapp.tar --checks all --fail-on any
```

| `--fail-on` | exits 1 when … |
|---|---|
| `any` (default) | any finding exists |
| `critical` | a `critical` finding exists |
| `high` | a `high` or `critical` finding exists |
| `medium` | `medium` or higher exists |
| `low` | `low` or higher exists |
| `info` | any finding exists (info is the floor) |
| `none` | never — report-only, always exits 0 on findings |

The threshold gates the exit code only; the rendered report (`json`/`h1md`/
`sarif`) always contains all findings so nothing is hidden from reviewers.

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

**Authentication.** Public registries (Docker Hub, GHCR, ECR, ACR) gate pulls
behind a bearer-token challenge: the registry replies `401 WWW-Authenticate:
Bearer realm=...`, the client fetches a token from the realm, then retries.
`casket` performs this negotiation automatically. Three options:

```bash
# anonymous pull of a public image (token negotiated, no credentials)
casket --image registry.hub.docker.com/library/alpine:3.19 --mode remote

# authenticated pull — credentials feed the token endpoint via HTTP Basic
casket --image ghcr.io/org/private:1.0 --mode remote \
       --registry-user "$GH_USER" --registry-password "$GH_TOKEN"

# a pre-issued static bearer token (internal registries)
casket --image http://registry.internal:5000/team/app:1.2 --mode remote \
       --token "$BEARER_TOKEN"
```

Credentials may also be supplied via the `CASKET_REGISTRY_USER` and
`CASKET_REGISTRY_PASSWORD` environment variables (preferred in CI so secrets
never appear in process listings or shell history). CLI flags take precedence
over env vars. Credentials are never logged.

> For AWS ECR, use `aws ecr get-login-password` as the `--registry-password`
> with `--registry-user AWS`.

### output formats

- `--format json` — the canonical machine-readable report. Every finding carries
  `category`, `severity`, `layer_sha`, and `path_in_layer`, plus category-specific
  fields (`rule` for creds/misconfig; `cve_id`, `package`, `installed_version`
  for CVEs). When the image config records build history, findings also carry
  `layer_command` — the Dockerfile instruction that introduced the layer (see
  [Layer command attribution](#layer-command-attribution)).
- `--format h1md` — a HackerOne-style markdown report for human submission.
- `--format sarif` — [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
  for CI/CD code-scanning ingest. Each finding type becomes a `rule` and each
  finding a `result`; severity maps to SARIF levels (CRITICAL/HIGH → `error`,
  MEDIUM → `warning`, LOW/INFO → `note`). Each rule and result also carries a
  `properties.security-severity` float — the CVSS-like score GitHub
  code-scanning uses to sort and gate findings (CRITICAL=9.5, HIGH=7.5,
  MEDIUM=5.0, LOW=2.0, INFO=0.0). Feed it straight to GitHub Advanced Security
  via `github/codeql-action/upload-sarif`.

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
  "rule": "aws_secret_access_key",
  "layer_command": "COPY .env /app/.env"
}
```

## Layer command attribution

Every finding records the `layer_sha` of the layer that introduced it. When the
image config carries OCI build `history` (almost all real images do), `casket`
goes one step further and attaches `layer_command` — the actual Dockerfile
instruction that created that layer, e.g. `RUN apt-get install -y openssl` or
`COPY .env /app/.env`. This turns "layer `sha256:abc…` leaked a key" into
"the `COPY .env /app/.env` step leaked a key", so you can fix the Dockerfile
directly instead of reverse-engineering which instruction produced a digest.

Attribution aligns the filesystem-bearing history entries with the layer list
in order; metadata-only steps (`ENV`, `WORKDIR`, `CMD`, …, marked
`empty_layer`) are skipped, matching the OCI image spec. The field appears in
all three output formats: as `layer_command` in `json`, a `**layer_command:**`
bullet in `h1md`, and a `properties.layer_command` entry in `sarif`. Findings
derived from the image config rather than a layer (misconfig checks) carry no
`layer_command`, since they belong to no single filesystem layer. If an image
ships without history, findings simply omit the field — nothing else changes.

## Credential coverage

The creds check scans the *contents* of every text file in every layer. It runs
two passes: a set of high-precision regex patterns first, then Shannon-entropy
analysis for anything that doesn't match a known format.

High-precision patterns (no entropy, negligible false-positive rate):

| group | patterns |
|---|---|
| AWS | secret access key, access key id |
| GitHub | personal access token (`ghp_`), OAuth (`gho_`), app/Actions (`ghs_`/`ghu_`) |
| Payments | Stripe live secret (`sk_live_`) and restricted (`rk_live_`) keys |
| Messaging | Slack (`xox[baprs]-`), SendGrid (`SG.`), Twilio account/API SIDs |
| Packaging | npm automation token (`npm_`), Docker Hub PAT (`dckr_pat_`) |
| Cloud / misc | GCP service-account key JSON, Heroku API key, Mailchimp key |
| Generic | API token/key assignments, JWTs (`eyJ…`), private-key blocks |

Each pattern carries its own severity (e.g. a Stripe live secret or GCP
service-account key is `critical`; a Twilio SID, which is lower-confidence, is
`medium`). The entropy pass catches custom/internal tokens that match no known
format and emits a redacted 8-character prefix for triage — never the full
secret. Rules live in `casket/ruledata/creds.yaml`; adding a pattern is a
one-line YAML edit.

## How CVE lookups stay polite

The CVE check extracts installed packages from four package databases and
resolves each `(ecosystem, name, version)` against OSV.dev:

| ecosystem | source | notes |
|---|---|---|
| PyPI | `*.dist-info/METADATA`, `*.egg-info/PKG-INFO` | |
| Debian | `var/lib/dpkg/status` | Debian/Ubuntu |
| Alpine | `lib/apk/db/installed` | `python:*-alpine`, `nginx:alpine`, etc. |
| Red Hat | `var/lib/rpm/rpmdb.sqlite` | RHEL 9+, Fedora, Amazon Linux 2023 |

OSV.dev keys Alpine vulnerabilities under **release-qualified** ecosystems
(`Alpine:v3.18`), not a bare `Alpine`. `casket` reads `etc/alpine-release` from
the image — scanning across layers, since it often lives in a different layer
than the package database — and queries the release-qualified ecosystem
(`Alpine:v3.18`) first, falling back to bare `Alpine` (under which the bundled
seed DB and on-disk cache are keyed) when no release marker is present. This is
what makes live Alpine CVE lookups against the OSV.dev API actually resolve.

The same release-qualified resolution applies to **Debian/Ubuntu**: OSV.dev
keys Debian vulnerabilities under `Debian:12` (the major release number), not a
bare `Debian`. `casket` reads the release from `etc/debian_version`, falling
back to the `VERSION_ID` field of `etc/os-release` (Ubuntu and `*-slim` images
that ship no `etc/debian_version`), scanning across layers. It queries the
release-qualified ecosystem (`Debian:12`) first and falls back to bare `Debian`
(under which the seed DB and cache are keyed) when no release marker is present.

RPM coverage reads the modern **SQLite** rpmdb only; the legacy Berkeley DB
`var/lib/rpm/Packages` (RHEL 7/8, CentOS 7) has no stdlib parser and is skipped
silently (no finding, no crash). RPM versions are matched as full EVR strings
(`epoch:version-release`, e.g. `1:3.0.7-6.el9`).

### CVE severity

Each CVE finding's severity is derived from the matched OSV record's standard
`severity` array — the CVSS vector OSV.dev records for the vast majority of
vulnerabilities. `casket` parses both CVSS **v3.x** and legacy CVSS **v2**
vectors, computes the base score with a small standard-library calculator (no
new dependency), and maps it to a qualitative band on the CVSS v3.1 scale
(`9.0–10.0` critical, `7.0–8.9` high, `4.0–6.9` medium, `0.1–3.9` low, `0.0`
info). Legacy v2 vectors are common on the older packages a container scanner
routinely surfaces; they are scored faithfully to the v2 formula but mapped
through the same unified band as v3 (so every finding speaks one severity
vocabulary, including `critical`, which v2's native scale lacks). CVSS v4.0
vectors are not yet scored (their base score is table-driven, not closed-form)
and fall through to the next source. If a record carries no scorable CVSS
vector, `casket` falls back to the record's `database_specific.severity`
string, and finally to a conservative `high`. Accurate severities matter
downstream: they drive the `--fail-on` CI gate and the SARIF `security-severity`
score that GitHub code-scanning uses to sort and threshold findings.

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
