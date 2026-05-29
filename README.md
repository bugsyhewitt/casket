# casket

**A daemonless, podman-native container image scanner. No Docker, no daemon, no root.**

`casket` inspects container images for three classes of problems and tells you
*which layer* introduced each one:

- **leaked credentials** — AWS keys, provider tokens (GitHub, Slack, Stripe,
  SendGrid, npm, GCP, Twilio, …), JWTs, private keys, and high-entropy secrets
- **known-vulnerable packages** — PyPI, Debian, Alpine, and RPM (RHEL/Fedora)
  packages resolved against [OSV.dev](https://osv.dev)
- **misconfigurations** — `USER root`, exposed ports (with sensitive service
  ports — SSH, databases, unencrypted Docker API — flagged at higher severity),
  secret-like env vars

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
       [--min-severity {all,critical,high,medium,low,info}]
       [--min-epss PROBABILITY]
       [--compare BASELINE.json]
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

The threshold gates the exit code only; by default the rendered report
(`json`/`h1md`/`sarif`) contains all findings so nothing is hidden from
reviewers. To prune the report itself, use `--min-severity` (below).

### Cutting report noise with `--min-severity`

`--fail-on` controls the *build outcome*; `--min-severity` controls *what gets
reported*. On a busy base image with hundreds of low-severity OS package CVEs,
you can suppress the noise and surface only what matters:

```bash
# report only high- and critical-severity findings
casket --image ./myapp.tar --checks all --min-severity high

# default: report everything (casket's original behaviour)
casket --image ./myapp.tar --checks all --min-severity all
```

| `--min-severity` | reports findings that are … |
|---|---|
| `all` (default) | every finding |
| `critical` | `critical` only |
| `high` | `high` or `critical` |
| `medium` | `medium` or higher |
| `low` | `low` or higher |
| `info` | any finding (info is the floor) |

The filter prunes the report **before** the `--fail-on` gate runs, so the build
outcome stays consistent with what you actually see: a finding you suppressed
from the report never secretly fails the build. The `finding_count` in JSON
output (and the SARIF/h1md bodies) reflect the filtered set. Combine the two for
a focused gate — e.g. report high+ and fail only on critical:

```bash
casket --image ./myapp.tar --checks all --min-severity high --fail-on critical
```

### Prioritising by exploitation likelihood with EPSS and `--min-epss`

CVSS severity answers "how *bad* is this vuln if exploited?" — it says nothing
about how *likely* exploitation is. On a busy base image carrying hundreds of
high-CVSS OS-package CVEs, the overwhelming majority are never actually
exploited, and severity alone gives you no way to tell which ones are.

[EPSS](https://www.first.org/epss/) (the Exploit Prediction Scoring System)
fills that gap: the FIRST.org model assigns every published CVE a **probability
(0.0–1.0)** that it will be exploited in the wild over the next 30 days, plus a
**percentile** rank against all scored CVEs. `casket` enriches every CVE finding
with its EPSS score and exposes it on the finding:

```json
{
  "category": "cve",
  "title": "requests 2.19.0: CVE-2018-18074",
  "severity": "medium",
  "cve_id": "CVE-2018-18074",
  "epss_score": 0.00427,
  "epss_percentile": 0.71234
}
```

`--min-epss PROBABILITY` then turns that into a triage knob: it reports only the
CVE findings the EPSS model rates at least that likely to be exploited, pruning
the long tail of high-CVSS-but-never-exploited noise.

```bash
# report only CVEs the model rates ≥ 10% likely to be exploited in the wild
casket --image ./myapp.tar --checks cves --min-epss 0.1

# combine with severity: only high+ findings that are also ≥ 50% likely
casket --image ./myapp.tar --checks all --min-severity high --min-epss 0.5
```

Behaviour and guarantees:

- The threshold is a probability and must be in `[0.0, 1.0]`; anything else is a
  clean argument error, not a traceback.
- The filter applies to **CVE findings only**. Leaked credentials and
  misconfigurations have no exploitation-probability score and are *never*
  pruned by `--min-epss` — they're a different class of problem.
- Like `--min-severity`, the filter shapes the **reported** set *before* the
  `--fail-on` gate (and `--compare` diff) run, so the build outcome stays
  consistent with what you actually see. The `finding_count` in JSON output
  reflects the filtered set.
- A CVE with **no published EPSS score** (the model only covers published CVEs;
  reserved, rejected, or very fresh ids are absent) does not clear an explicit
  `--min-epss` bar and is pruned. Without the flag, scores are still surfaced;
  CVEs with no score simply omit the `epss_score` key entirely (so existing
  output stays byte-compatible).

Scores come from a public, read-only `GET` to the FIRST.org EPSS API — all of an
image's CVEs resolve in **one** batched request, and every result is cached to
`~/.cache/casket/epss-cache.json` (override with `CASKET_EPSS_CACHE`).
`--offline` forbids the network entirely: cached scores still apply, and CVEs
with no cached score simply carry no EPSS field (and are pruned by an explicit
`--min-epss`). A network failure degrades the same way — never a crash, and the
miss is left uncached so a later online run retries.

### Diffing two scans with `--compare`

A container image is rebuilt constantly. The CI question is rarely "what
findings does this image have?" (often a large, slow-moving wall of OS-package
CVEs) but **"did *this* build introduce anything new versus the last
known-good scan?"** `--compare` answers exactly that: it takes a previously
saved casket JSON report as a baseline, diffs the current scan against it, and
emits a diff document — and it exits `1` **only when this build adds new
findings** (regressions), `0` otherwise.

```bash
# 1. record a baseline from a known-good image (e.g. the last release)
casket --image ./myapp:released.tar --checks all --format json > baseline.json

# 2. on every build, diff the new image against that baseline
casket --image ./myapp:candidate.tar --checks all --compare baseline.json
#   exit 0: no new findings  |  exit 1: this build introduced something new
```

The diff classifies every finding into four buckets:

| bucket | meaning | gates the build? |
|---|---|---|
| `added` | present now, absent in the baseline — a **regression** | **yes** (exit 1) |
| `removed` | in the baseline, gone now — fixed | no |
| `changed` | same finding, but its **severity moved** (e.g. a CVE re-scored medium → critical) | no |
| `unchanged` | identical in both scans | no |

Finding identity is matched on the issue's **semantics**, not on volatile build
artifacts: `layer_sha` (a rebuild produces fresh digests for identical content),
`summary`, and `layer_command` are all ignored, so a plain rebuild reports
everything as `unchanged` rather than added+removed. `severity` is excluded from
identity but compared separately, which is what surfaces re-scored CVEs as
`changed` instead of losing them to an added/removed pair.

```jsonc
{
  "tool": "casket",
  "diff": true,
  "baseline_image": "./myapp:released.tar",
  "current_image": "./myapp:candidate.tar",
  "summary": { "added": 1, "removed": 0, "changed": 1, "unchanged": 42 },
  "added":     [ /* full current findings that are new */ ],
  "removed":   [ /* full baseline findings now gone */ ],
  "changed":   [ { "from_severity": "medium", "to_severity": "critical",
                   "finding": { /* current finding */ } } ],
  "unchanged": [ /* … */ ]
}
```

`--min-severity` is applied to the current scan **before** diffing, so you can
diff at a chosen severity floor (e.g. `--min-severity high --compare baseline.json`
only ever considers high+ findings on both sides). `--fail-on` is ignored in
compare mode — the diff gates on *new* findings instead, which is the
actionable CI signal. The baseline must be a casket `--format json` report; any
other file produces a clean exit-2 error rather than a traceback.

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
  for CVEs). CVE findings also carry the remediation version, cross-reference
  identifiers, and remediation links the OSV record provides — `fixed_versions`,
  `aliases`, `fix_urls`, `advisory_urls`, `exploit_urls` (see
  [CVE remediation, references & aliases](#cve-remediation-references--aliases)),
  plus the EPSS exploitation-probability score (`epss_score`, `epss_percentile`;
  see [Prioritising by exploitation likelihood with EPSS](#prioritising-by-exploitation-likelihood-with-epss-and---min-epss)).
  When the image config
  records build history, findings also carry `layer_command` — the Dockerfile
  instruction that introduced the layer (see
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

## CVE remediation, references & aliases

A CVE finding answers more than "which package has which CVE" — it also tells
you **what to upgrade to** and **where to go next**. Every OSV record `casket`
resolves already carries the fix version, the upstream cross-references, and the
remediation links, so `casket` surfaces them on the finding with **no extra
network call** (the data rides along with the severity lookup `casket` already
performs and caches):

| field | source | what it gives you |
|---|---|---|
| `fixed_versions` | OSV `affected[].ranges[].events[].fixed` | the version(s) to upgrade to that resolve the vuln |
| `aliases` | OSV `aliases` | the full id list for the same vuln (CVE + GHSA + distro ids), de-duplicated |
| `fix_urls` | OSV `references` type `FIX` | the patch / remediation commit(s) |
| `advisory_urls` | OSV `references` types `ADVISORY`, `REPORT` | the advisory write-up(s) |
| `exploit_urls` | OSV `references` types `EXPLOIT`, `EVIDENCE` | known proof-of-concept / exploit link(s) |

Each field is a list, de-duplicated and in first-seen order. A field is **omitted
entirely** when the OSV record carries nothing for it — so a finding with no
known patch simply has no `fix_urls` key, and a **still-unfixed** vuln (no
`fixed` event in its OSV ranges) has no `fixed_versions` key, rather than an
empty one. `fixed_versions` is the single most actionable field: it turns "this
package has a CVE" into "...upgrade to X to fix it". The headline `cve_id` still
prefers a `CVE-…` alias when present, falling back to the raw OSV id; `aliases`
exposes the rest. All fields flow through every output format: top-level keys in
`json`, bullets in `h1md`, and `result.properties` entries in `sarif`.

This is the GHSA / NVD remediation enrichment value without an external API
dependency or rate-limit/auth concerns — OSV's own `affected` ranges and
`references` already aggregate the fix version, the upstream advisory, and the
patch links.

```json
{
  "category": "cve",
  "title": "requests 2.19.0: CVE-2018-18074",
  "severity": "medium",
  "cve_id": "CVE-2018-18074",
  "osv_id": "GHSA-x84v-xcm2-53pg",
  "package": "requests",
  "installed_version": "2.19.0",
  "fixed_versions": ["2.20.0"],
  "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
  "fix_urls": ["https://github.com/psf/requests/commit/c45d…"],
  "advisory_urls": ["https://github.com/advisories/GHSA-x84v-xcm2-53pg"]
}
```

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

## Misconfiguration coverage

The misconfig check inspects the image *config* (the merged Dockerfile-equivalent
settings) rather than layer file contents:

| check | what it flags | severity |
|---|---|---|
| `running_as_root` | `config.User` empty or `root`/`0` | high |
| `sensitive_port` | a well-known sensitive service port is exposed | per-port (see below) |
| `exposed_port` | any other network port is exposed | low |
| `suspicious_env_var` | an env var *name* matches a secret-ish pattern | medium |

### Sensitive service ports

A container exposing SSH or a database is a materially different risk than one
exposing an application port. `casket` recognizes a curated set of well-known
sensitive service ports and flags them at higher severity than a generic
`EXPOSE`, surfacing the **service name** on the finding (`service` field) so an
operator can triage without looking the port up:

| port(s) | service | severity |
|---|---|---|
| 2375 | Docker API (unencrypted) | critical |
| 22 | SSH | high |
| 23 | Telnet | high |
| 2376 | Docker API (TLS) | high |
| 2379 / 2380 | etcd (client / peer) | high |
| 3306 | MySQL/MariaDB | high |
| 5432 | PostgreSQL | high |
| 6379 | Redis | high |
| 9200 | Elasticsearch | high |
| 11211 | Memcached | high |
| 27017 | MongoDB | high |
| 5984 | CouchDB | high |
| 8500 | Consul | high |
| 5900 | VNC | high |
| 3389 | RDP | high |

Matching is on the port *number*, regardless of the `/tcp` or `/udp` suffix in
`config.ExposedPorts`. A sensitive port produces a **single** higher-signal
finding — it is not also reported by the generic `exposed_port` rule, so there
are no duplicate findings. Every other exposed port still falls through to the
generic `exposed_port` rule at `low` severity. The list lives in
`casket/ruledata/misconfig.yaml` and is a one-line YAML edit to extend.

```json
{
  "category": "misconfig",
  "title": "Image exposes a sensitive service port",
  "severity": "high",
  "rule": "sensitive_port",
  "port": "5432/tcp",
  "service": "PostgreSQL"
}
```

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
vulnerabilities. `casket` parses CVSS **v4.0**, **v3.x**, and legacy CVSS **v2**
vectors, computes the base score with a small standard-library calculator (no
new dependency), and maps it to a qualitative band on the CVSS v3.1 scale
(`9.0–10.0` critical, `7.0–8.9` high, `4.0–6.9` medium, `0.1–3.9` low, `0.0`
info). Legacy v2 vectors are common on the older packages a container scanner
routinely surfaces; they are scored faithfully to the v2 formula but mapped
through the same unified band as v3/v4 (so every finding speaks one severity
vocabulary, including `critical`, which v2's native scale lacks). CVSS v4.0's
base score is not a closed-form formula — it is a MacroVector lookup plus
severity-distance interpolation — so `casket` implements the
[FIRST CVSS v4.0 algorithm](https://www.first.org/cvss/v4-0/specification-document)
faithfully (validated bit-for-bit against the FIRST reference calculator across
the full base-metric space). If a record carries no scorable CVSS vector,
`casket` falls back to the record's `database_specific.severity` string, and
finally to a conservative `high`. Accurate severities matter downstream: they
drive the `--fail-on` CI gate, the `--min-severity` report filter, and the SARIF
`security-severity` score that GitHub code-scanning uses to sort and threshold
findings.

Results are cached to `~/.cache/casket/osv-cache.json` (override with
`CASKET_OSV_CACHE`). A bundled read-only seed DB resolves a small curated set
with no network at all. Pass `--offline` to forbid network access entirely.

### Batched OSV queries

A busy `debian`/`ubuntu` image can carry hundreds of installed packages. Rather
than issue one HTTP request per package, `casket` resolves them **cache-first,
then in a single batched request**: every package is checked against the
on-disk cache and bundled seed DB first (a fully cached or offline scan touches
no network), and only the packages that miss locally are sent — all together —
to OSV.dev's `/v1/querybatch` endpoint. The (typically small) set of vulnerable
packages is then hydrated to full records for severity scoring and cached
per package, so on a clean image hundreds of round-trips collapse to one. The
behaviour is otherwise unchanged: misses degrade to empty (never a crash, and
they stay uncached so a later online run can retry), and the release-qualified
ecosystem candidates above are tried in the same order.

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
