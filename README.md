# casket

**A daemonless, podman-native container image scanner. No Docker, no daemon, no root.**

`casket` inspects container images for three classes of problems and tells you
*which layer* introduced each one:

- **leaked credentials** — AWS keys, provider tokens (GitHub, Slack, Stripe,
  SendGrid, npm, GCP, Twilio, Azure, OpenAI, Anthropic, Databricks, Vault, …),
  JWTs, private keys, and high-entropy secrets
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
       [--suppress-severity {critical,high,medium,low,info}]
       [--min-epss PROBABILITY]
       [--cvss-floor SCORE]
       [--vex VEX.json] [--vex-max-age DAYS]
       [--suppress-ecosystem ECOSYSTEM]
       [--purl-filter PATTERN]
       [--only-actionable]
       [--compare BASELINE.json] [--diff-format {json,h1md}]
       [--group-by-package]
       [--stats]
       [--output-json-summary]
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

### Muting exact severity bands with `--suppress-severity`

`--min-severity` is a *floor* — it keeps everything at or above one threshold.
But sometimes you want to keep the genuine risk (critical/high) **and** the
audit-trail noise floor (info) while muting only the busy middle, or mute one
band without dropping everything beneath it. A single floor can't express that.
`--suppress-severity` mutes the named severity band(s) *exactly*, and is
repeatable:

```bash
# keep critical/high AND info, drop the busy medium/low middle
casket --image ./myapp.tar --checks all \
  --suppress-severity medium --suppress-severity low

# mute the high band alone, keeping critical and everything below high
casket --image ./myapp.tar --checks all --suppress-severity high
```

| flag | effect |
|---|---|
| `--min-severity high` | keep `high` + `critical` (a floor) |
| `--suppress-severity high` | drop `high` only; keep every other band |
| `--suppress-severity medium --suppress-severity low` | drop the `medium`/`low` middle; keep critical/high/info |

- Applies to **every** finding category (creds / cve / misconfig all carry a
  severity), unlike the CVE-only `--min-epss` / `--cvss-floor` / `--vex` /
  `--suppress-ecosystem` filters.
- A finding with an unrecognised severity is never muted by it (an unknown band
  is never silently hidden).
- Like `--min-severity` / `--min-epss` / `--vex` / `--suppress-ecosystem`, the
  filter shapes the **reported** set *before* the `--fail-on` gate and
  `--compare` diff run, so a muted band neither shows up nor secretly trips the
  build. It composes with `--min-severity` as an independent stage.

### Focusing on fixable CVEs with `--only-actionable`

Container images routinely carry OS-package CVEs for which no patch has been
published yet. On a busy `debian`/`ubuntu`/`alpine` base image these *unfixed*
CVEs can make up the majority of a scan report, obscuring the vulnerabilities you
can actually remediate today.

`--only-actionable` mirrors Trivy's `--ignore-unfixed` and Grype's fixed-status
filter: it drops CVE findings that have **no known fix**, keeping only those
where the OSV record has published at least one patched version
(`detail["fixed_versions"]` is non-empty). Credentials and misconfig findings
always survive — their remediation is inherent (remove the secret, fix the
Dockerfile), so they are always actionable by nature.

```bash
# report only CVEs that have a patch available
casket --image ./myapp.tar --checks cves --only-actionable

# combine with --min-severity to focus on fixable high+ CVEs
casket --image ./myapp.tar --checks all --min-severity high --only-actionable

# combine with --fail-on to break the build only on fixable criticals
casket --image ./myapp.tar --checks all --only-actionable --fail-on critical
```

Behaviour and guarantees:

- **CVE findings only.** Credentials and misconfig findings are never dropped.
- **Consistent with the gate.** Like `--min-severity` / `--min-epss` / `--vex`,
  the filter shapes the **reported** set *before* the `--fail-on` gate and
  `--compare` diff, so a dropped unfixed CVE never secretly trips the build —
  what fails the build matches what you see.
- **Composable.** Stacks with every other filter; apply as many simultaneously as
  needed.
- **No network.** `fixed_versions` is extracted from the cached OSV record — no
  new API calls.

---

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

### Numeric CVSS cutoffs with `--cvss-floor`

`--min-severity high` keeps every CVE scored 7.0-10.0 — a 7.0 and a 9.8 are
both `high` even though the 9.8 is materially more urgent. The qualitative
band is a *range*; sometimes you want the *number*. `--cvss-floor SCORE`
reports only CVE findings whose `cvss_score` is at or above the threshold, so
an operator can carve any cutoff inside (or across) a band — e.g. "only
critical-or-near-critical: score >= 8.5".

```bash
# report only CVE findings whose CVSS base score is >= 7.5
casket --image ./myapp.tar --checks cves --cvss-floor 7.5

# stack with the other filters: high+ that are also >= 8.5 AND >= 10% likely
casket --image ./myapp.tar --checks all \
       --min-severity high --cvss-floor 8.5 --min-epss 0.1
```

Behaviour and guarantees:

- The threshold is a CVSS base score and must be in `[0.0, 10.0]` (the bounds
  of every CVSS version: v2, v3.x, v4.0). Anything else is a clean argument
  error, not a traceback.
- The filter applies to **CVE findings only**. Leaked credentials and
  misconfigurations have no CVSS score (they're a different class of problem)
  and are *never* pruned by `--cvss-floor`.
- A CVE finding whose OSV record carries **no scorable CVSS vector** (severity
  then came from the record's `database_specific` string or the conservative
  default — see [CVE severity](#cve-severity)) does not clear an explicit
  floor and is pruned, matching `--min-epss`'s posture. Without the flag,
  unscored CVEs simply omit the `cvss_score` key (existing output stays
  byte-compatible).
- Like the other report filters, `--cvss-floor` shapes the **reported** set
  *before* the `--fail-on` gate (and `--compare` diff) run, so the build
  outcome stays consistent with what you actually see. The `finding_count` in
  JSON output reflects the filtered set.
- Composes with `--min-severity` as an independent stage: `--min-severity` is
  a *band* floor; `--cvss-floor` is a *numeric* floor. The intersection is
  applied — a finding must clear both.
- Network-free: the score is already on the finding (computed by `casket`
  from the OSV record's CVSS vector during the severity lookup); the filter
  adds zero requests.

### Suppressing triaged CVEs with VEX and `--vex`

`--min-severity` and `--min-epss` cut noise *heuristically*. VEX lets you cut it
*deliberately*: an [OpenVEX](https://openvex.dev) document records the CVEs a
human has already triaged as **not exploitable in this image** — the vulnerable
code path is never reached, the affected component isn't shipped, or a
backported patch fixed it without bumping the version string. Every mature
scanner consumes VEX for exactly this (Trivy/Grype VEX, GitHub dismissals);
casket reads an OpenVEX JSON file and drops the matching CVE findings.

```bash
# suppress the CVEs your VEX document marks not_affected / fixed
casket --image ./myapp.tar --checks cves --vex ./vex.json

# stacks with the other filters — triage, then prioritise
casket --image ./myapp.tar --checks all --vex ./vex.json --min-epss 0.1
```

A minimal VEX document:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [
    { "vulnerability": { "name": "CVE-2018-18074" }, "status": "not_affected" },
    { "vulnerability": "CVE-2021-0001", "status": "fixed" }
  ]
}
```

- Only `not_affected` and `fixed` statements suppress — they mean "do not report
  this against this image". `affected` / `under_investigation` statements are
  ignored (you're telling casket to *keep* showing those).
- A statement's `vulnerability` may be the spec object `{"name": "CVE-…"}` or a
  bare string (`"CVE-…"`); either works.
- Matching is robust: a CVE finding is suppressed when **any** of its
  identifiers — the headline CVE id, the raw OSV id, or any cross-reference
  alias — is named by a suppressing statement. So a VEX entry written against a
  `CVE-…` still suppresses a finding whose OSV headline is a `GHSA-…`, and
  vice-versa.
- VEX is a CVE-triage format: `creds` and `misconfig` findings are **never**
  pruned by `--vex`.
- Like the other filters, `--vex` shapes the **reported** set *before* the
  `--fail-on` gate (and `--compare` diff) run, so a triaged-away CVE neither
  shows up in the report nor secretly trips the build gate.
- A missing or malformed VEX file is a clean exit `2` (with a one-line stderr
  message), never a traceback. Individual malformed statements are skipped so a
  single bad row doesn't void an otherwise-usable file.

#### Expiring stale triage with `--vex-max-age`

A triage decision is a point-in-time judgement. A CVE waived as `not_affected`
six months ago may have become reachable since — a new base layer, a new
dependency, a freshly-disclosed exploit chain. A suppression that lives forever
silently is a stale-triage hazard: the operator stops seeing the CVE and forgets
it was ever waived. OpenVEX statements carry a `timestamp` (and the document
carries one its statements inherit); `--vex-max-age DAYS` uses it to enforce a
re-triage window.

```bash
# suppressions older than 90 days expire — the CVE re-surfaces, forcing review
casket --image ./myapp.tar --checks cves --vex ./vex.json --vex-max-age 90
```

A timestamped statement:

```json
{
  "statements": [
    {
      "vulnerability": { "name": "CVE-2018-18074" },
      "status": "not_affected",
      "timestamp": "2026-01-15T00:00:00Z"
    }
  ]
}
```

- With `--vex-max-age N`, a suppressing statement whose `timestamp` is **more
  than N days** before now is treated as **expired**: the CVE it waived
  re-surfaces in the report and (re-)trips the `--fail-on` gate. A statement
  exactly at the window edge is still live.
- A suppression that carries **no timestamp** (neither on the statement nor on
  the document) can't be proven inside the window, so under `--vex-max-age` it
  is treated as expired too. Date your waivers if you want them to survive a
  window.
- The flag requires `--vex`; on its own it is inert (there are no suppressions
  to expire). It takes a positive whole number of days.
- Omit the flag (the default) to keep every suppression forever regardless of
  its timestamp — the original `--vex` behaviour is unchanged.

### Suppressing whole ecosystems with `--suppress-ecosystem`

On most images the noisiest CVEs come from the base OS layer — hundreds of
Debian/Alpine/Red Hat package CVEs you don't own and patch on the distro's
cadence, not yours. When you want to focus a review on the **application**
dependencies you actually control (PyPI/npm/…), `--suppress-ecosystem` drops
every CVE finding from a named [OSV ecosystem](https://ossf.github.io/osv-schema/#defined-ecosystems):

```bash
# hide all Debian OS-package CVEs, keep everything else
casket --image ./myapp.tar --checks cves --suppress-ecosystem Debian

# mute several OS ecosystems at once (the flag is repeatable)
casket --image ./myapp.tar --checks all \
  --suppress-ecosystem Debian --suppress-ecosystem Alpine

# combine with the other report filters — they all shape the same reported set
casket --image ./myapp.tar --checks all --suppress-ecosystem Debian --min-epss 0.1
```

- Matching is **case-insensitive**, so you needn't remember OSV's exact
  capitalisation — `Debian`, `debian`, `Red Hat`, and `red hat` all match.
- Only **CVE** findings carry an ecosystem, so `creds` and `misconfig` findings
  are never pruned by this flag — it is purely a CVE-noise knob.
- A CVE finding that carries **no** ecosystem is always kept: it can't be matched
  against the suppress list, so it's never silently hidden.
- Like `--min-severity` / `--min-epss` / `--vex`, the filter shapes the
  **reported** set *before* the `--fail-on` gate and the `--compare` diff, so a
  CVE suppressed by ecosystem neither shows up in the report nor trips the gate —
  what fails the build matches what you see.
- This is a *suppression* knob, not a *selection* one: to scan only certain
  check types use `--checks`; to keep only certain ecosystems, suppress the rest.
- Omit the flag (the default) to report every finding regardless of ecosystem.

### Selecting CVEs by package with `--purl-filter`

`--suppress-ecosystem` is the *mute* knob at the ecosystem level — drop a whole
distro's CVE noise. `--purl-filter` is the **selection** knob at the package
level — keep only the CVE findings whose installed component matches a
[Package URL](https://github.com/package-url/purl-spec) glob, so an operator
can carve a focused scan around the exact packages they care about:

```bash
# keep only application-dependency CVEs (every PyPI package), drop the OS noise
casket --image ./myapp.tar --checks cves --purl-filter 'pkg:pypi/*'

# focus on openssl across every distro (Debian, RHEL, Alpine all matched at once)
casket --image ./myapp.tar --checks cves --purl-filter 'pkg:*/openssl@*'

# repeatable: multiple patterns OR — keep PyPI app deps and any openssl
casket --image ./myapp.tar --checks cves \
  --purl-filter 'pkg:pypi/*' --purl-filter 'pkg:*/openssl@*'

# pin to a specific version range (fnmatch glob)
casket --image ./myapp.tar --checks cves --purl-filter 'pkg:pypi/requests@2.*'
```

`casket` synthesizes each CVE finding's purl from its
`(ecosystem, package, installed_version)` and matches it against the operator's
patterns. The mapping follows the
[purl-spec canonical types](https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst):

| ecosystem | purl type | example |
|---|---|---|
| PyPI | `pypi` | `pkg:pypi/requests@2.19.0` |
| Debian | `deb` | `pkg:deb/openssl@3.0.7-1` |
| Alpine | `apk` | `pkg:apk/busybox@1.36.0-r0` |
| Red Hat | `rpm` | `pkg:rpm/openssl@1:3.0.7-6.el9` |

Behaviour and guarantees:

- Patterns use [`fnmatch`](https://docs.python.org/3/library/fnmatch.html) glob
  semantics (`*`, `?`, `[seq]`), the same family the shell uses. Multiple
  `--purl-filter` patterns OR (a finding survives if **any** pattern matches),
  so the flag is repeatable.
- Matching is **case-insensitive** so an operator needn't remember the
  canonical lowercased purl type spelling (`pkg:PyPI/...` and `pkg:pypi/...`
  both match).
- Only **CVE** findings carry package identity, so `creds` and `misconfig`
  findings are *never* pruned by this flag — purl is a package addressing
  scheme, and credential/misconfiguration noise is a different question.
- A CVE finding missing `ecosystem`, `package`, or `installed_version` produces
  no purl and so cannot match any pattern — it is pruned by an explicit
  `--purl-filter` (matching `--cvss-floor` / `--min-epss` posture: an explicit
  selection bar requires the data to evaluate it). Without the flag, every
  finding still surfaces.
- Like `--min-severity` / `--min-epss` / `--vex` / `--suppress-ecosystem`, the
  filter shapes the **reported** set *before* the `--fail-on` gate and
  `--compare` diff, so a CVE pruned by purl neither shows up in the report nor
  trips the build gate — what fails the build matches what you see. The
  `finding_count` in JSON output reflects the filtered set.
- Composes with the other filters: `--purl-filter 'pkg:pypi/*' --min-severity high`
  reports only PyPI app-dependency CVEs that are also `high+`.
- This is a *selection* knob, not a *suppression* one. To mute a noisy
  ecosystem use `--suppress-ecosystem`; to keep only certain packages, select
  them with `--purl-filter`.
- Omit the flag (the default) to report every finding regardless of package.

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

#### Human-readable diff with `--diff-format h1md`

The JSON diff above is the canonical machine form — but for PR comments, Slack
snippets, or build-log artefacts the operator usually wants something they can
read at a glance. `--diff-format h1md` re-renders the same diff as Markdown:

```bash
casket --image ./myapp:candidate.tar --checks all \
       --compare baseline.json --diff-format h1md
```

Produces a structured summary, sorted worst-severity-first within each bucket:

```markdown
# casket scan diff

- **baseline:** `./myapp:released.tar`
- **current:** `./myapp:candidate.tar`

**Summary:** added `1`, removed `0`, changed `1`, unchanged `42`

## Added (1)

_New findings introduced by this build (regressions)._

- **[CRITICAL]** `aws_secret_key` — `app/.env`

## Removed (0)

_None._

## Changed (1)

_Same finding, severity moved (re-scored)._

- **[MEDIUM -> CRITICAL]** `CVE-2024-00123` — `urllib3@1.26.0` [PyPI]

## Unchanged (42)

_42 finding(s) carry over from the baseline unchanged._
```

`unchanged` collapses to a count line on purpose — the diff exists to surface
deltas, not re-render the stable wall. `--diff-format json` is the default, so
existing `--compare` consumers (and any tooling that parses the diff JSON) keep
working unchanged. The exit-code gate (new findings → exit 1) is identical
across formats; only the serialization changes. Outside `--compare` the flag is
silently inert.

### Component-count inventory with `--stats`

`finding_count` tells you how many *vulnerabilities* a scan found — but not how
big the image's attack surface is, or how much of it is actually affected. A
single ancient package can carry a dozen CVEs and inflate `finding_count` while
only *one* component is at fault. `--stats` adds a component-count inventory
summary so you can see the shape of what was scanned:

```bash
# add a component-count summary to the report
casket --image ./myapp.tar --checks cves --stats
```

In `--format json` (and via `--compare`) this is a `scan_stats` object:

```json
"scan_stats": {
  "total_components": 412,
  "by_ecosystem": { "Debian": 405, "PyPI": 7 },
  "vulnerable_components": 3,
  "severity_histogram": { "critical": 1, "high": 4, "medium": 2 }
}
```

- `total_components` — every installed package casket extracted across all
  layers (PyPI, Debian/Ubuntu, Alpine, RPM).
- `by_ecosystem` — the per-ecosystem breakdown, sorted by descending count.
- `vulnerable_components` — the number of **distinct** packages (name@version)
  with at least one reported CVE. Computed from the *filtered* findings, so a
  CVE triaged away by `--min-severity` / `--min-epss` / `--vex` is no longer
  counted as a vulnerable component — the number matches what you see.
- `severity_histogram` — finding counts per severity over **every** check
  (creds, cve, *and* misconfig), ordered most-severe-first (`critical` →
  `info`); severities with no findings are omitted. Where `finding_count`
  answers "how many issues?", this answers "what's the severity distribution?"
  — the canonical triage question. Like the other stats it counts the
  *filtered* findings, so the histogram sums to `finding_count`.

In `--format h1md` it renders as a **Components** section; in `--format sarif`
it rides along as a run-level `properties.scan_stats` object. Omitting the flag
leaves output byte-for-byte unchanged (default).

This is a count of the partial package inventory casket already reads while
scanning — it does **not** generate an SBOM (CycloneDX/SPDX), stays inside the
daemonless / no-SBOM-generation architecture, and adds **zero** network calls
(the inventory is extracted from layer files; `--stats` works fully `--offline`).

### Dashboard / metric output with `--output-json-summary`

`--format json` is the canonical per-finding report — the right shape for
triage, `--compare` diffing, and SARIF / h1md rendering. But on a CI dashboard
or a per-build metrics pipeline you usually want a single compact object with
counts and a small top-N preview, not the full findings list.
`--output-json-summary` emits exactly that:

```bash
casket --image ./myapp.tar --checks all --output-json-summary
```

```json
{
  "tool": "casket",
  "version": "0.1.0",
  "image": "./myapp.tar",
  "finding_count": 17,
  "by_severity": { "critical": 1, "high": 4, "medium": 8, "low": 4 },
  "by_category": { "cve": 14, "creds": 2, "misconfig": 1 },
  "by_ecosystem": { "Debian": 12, "PyPI": 2 },
  "top_cves": [
    {
      "severity": "critical",
      "cve_id": "CVE-2024-0001",
      "package": "openssl",
      "installed_version": "3.0.7-1",
      "ecosystem": "Debian",
      "epss_score": 0.92,
      "cvss_score": 9.8
    }
  ]
}
```

The summary is a sibling output mode to `--format json`, not a replacement:

- It carries **counts**, **histograms**, and a **top-10 CVE preview** ordered
  worst-severity-first (then EPSS-desc, then CVE id). It deliberately omits
  the full per-finding `detail` blob, layer attribution, CVSS vectors, and fix
  URLs — those live in the full `--format json` report.
- When `--stats` is also set, the inventory counts (`total_components`,
  `vulnerable_components`, `components_by_ecosystem`) are surfaced as
  first-class top-level keys for one-line `jq` access.
- It honours every report filter (`--min-severity`, `--min-epss`, `--vex`,
  `--suppress-ecosystem`, `--suppress-severity`), so the summary reflects what
  the full report would show — what fails the build matches what the dashboard
  sees.
- It honours the `--fail-on` exit-code gate, so the build outcome stays
  consistent across the two output modes.
- `--format` is ignored: the summary is JSON-only by design (a dashboard reads
  JSON).
- Mutually exclusive with `--compare` (different output modes; combining them
  surfaces a clean exit-2 error rather than silently letting one win).

Typical CI use:

```bash
# fail the build on critical+, but also publish the summary for the dashboard
casket --image ./img.tar --checks all --fail-on critical --output-json-summary \
  | tee scan-summary.json \
  | jq '.by_severity.critical + .by_severity.high'
```

Omitting the flag keeps the full findings report (default).

### Grouping CVE findings by package with `--group-by-package`

A single ancient package can carry a dozen CVEs, and an h1md report
that spells them out one section per CVE drowns the operator in
repeated package/version headers. `--group-by-package` collapses every
CVE finding that shares an installed `(package, installed_version)`
into one section in h1md output:

```bash
casket --image ./myapp.tar --checks cves --format h1md --group-by-package
```

```markdown
## Package: `openssl@3.0.0` [CRITICAL]

- **layer:** `sha256:abc…`
- **path:** `var/lib/dpkg/status`
- **ecosystem:** `Debian:12`
- **CVE count:** `3`

- **[critical]** `CVE-2024-0002` — heap buffer overflow in TLS handshake
- **[high]** `CVE-2024-0001` — use-after-free in X509 parser
- **[low]** `CVE-2024-0003` — timing leak in HMAC compare
```

The section header surfaces the **worst** severity among the package's
CVEs so triage order isn't lost; each bullet still shows its own
severity band. Sections are emitted worst-package-first.

Behaviour to know:

- **h1md only.** `--format json` and `--format sarif` are byte-for-byte
  unchanged with or without the flag — machine consumers (`--compare`,
  GitHub code-scanning ingest) stay stable, and CI gates (`--fail-on`)
  see the same finding set either way.
- **Different installed versions stay separate.** Multi-stage builds
  and overlay images can ship two copies of one package at different
  versions; `openssl@3.0.0` and `openssl@1.1.1k` get their own
  sections.
- **Creds and misconfig findings render unchanged.** They carry no
  `package` field and aren't a triage-by-package workflow, so they
  keep their per-finding headers below the package sections.
- A defensive CVE missing a `package` field falls back to the
  per-finding layout (it isn't silently dropped).

Omitting the flag keeps the per-finding section layout (default).

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
| `cvss_score` | OSV `severity[].score` (CVSS vector, scored by `casket`) | the numeric base score (e.g. `9.8`) — where the finding sits *within* its severity band |
| `cvss_version` | OSV `severity[].type` / vector prefix | which CVSS revision produced the score: `"2.0"`, `"3.x"`, or `"4.0"` |
| `cvss_vector` | OSV `severity[].score` | the source vector string the score and band were computed from |
| `cvss_supplemental` | CVSS v4.0 Supplemental Metric Group (FIRST spec section 2.4) | decoded extrinsic triage signal (Safety, Automatable, Recovery, Value Density, Response Effort, Provider Urgency) — does not affect the base score |
| `fixed_versions` | OSV `affected[].ranges[].events[].fixed` | the version(s) to upgrade to that resolve the vuln |
| `aliases` | OSV `aliases` | the full id list for the same vuln (CVE + GHSA + distro ids), de-duplicated |
| `fix_urls` | OSV `references` type `FIX` | the patch / remediation commit(s) |
| `advisory_urls` | OSV `references` types `ADVISORY`, `REPORT` | the advisory write-up(s) |
| `exploit_urls` | OSV `references` types `EXPLOIT`, `EVIDENCE` | known proof-of-concept / exploit link(s) |

The reference fields (`fix_urls`, `advisory_urls`, `exploit_urls`, `aliases`,
`fixed_versions`) are lists, de-duplicated and in first-seen order. A field is
**omitted entirely** when the OSV record carries nothing for it — so a finding
with no known patch simply has no `fix_urls` key, and a **still-unfixed** vuln
(no `fixed` event in its OSV ranges) has no `fixed_versions` key, rather than an
empty one. `fixed_versions` is the single most actionable field: it turns "this
package has a CVE" into "...upgrade to X to fix it". The headline `cve_id` still
prefers a `CVE-…` alias when present, falling back to the raw OSV id; `aliases`
exposes the rest.

The `cvss_score`, `cvss_version`, and `cvss_vector` fields surface the **numeric**
CVSS base score `casket` already computes when deriving the severity band (see
[CVE severity](#cve-severity)). The qualitative `severity` tells you the bucket;
`cvss_score` tells you where the finding sits *within* it — a `9.8` and a `9.0`
are both `critical`, but the first is more urgent — and `cvss_vector` shows the
attack shape that produced it (network vs. local, privileges required, impact).
These three keys are **omitted together** when the OSV record carries no scorable
CVSS vector (severity then came from the record's `database_specific` string or
the conservative default, so there is no number to surface).

For CVE findings scored from a **CVSS v4.0** vector that carries any
[Supplemental Metric Group](https://www.first.org/cvss/v4-0/specification-document)
values, `casket` also surfaces a `cvss_supplemental` object decoding those
metrics into operator-readable labels:

| key | source metric | values |
|---|---|---|
| `safety` | `S` — impact on human Safety (IEC 61508) | `negligible`, `present` |
| `automatable` | `AU` — can the attack be automated across many targets? | `no`, `yes` |
| `recovery` | `R` — system recoverability after exploit | `automatic`, `user`, `irrecoverable` |
| `value_density` | `V` — density of the controlled resource | `diffuse`, `concentrated` |
| `response_effort` | `RE` — effort to deploy the fix | `low`, `moderate`, `high` |
| `provider_urgency` | `U` — vendor-asserted patch urgency (TLP-coloured) | `clear`, `green`, `amber`, `red` |

These metrics convey *extra extrinsic context* that the base score deliberately
does not encode (a `7.5` with `safety: present` is qualitatively different from
a `7.5` with `safety: negligible`; `provider_urgency: red` is a vendor's own
"patch now" signal). They are **parsed-and-ignored for scoring** — the band, the
`--fail-on` gate, and the SARIF `security-severity` float are byte-identical
with or without them. Individual keys are omitted when the source metric is
absent or `X` (Not Defined), and the whole block is omitted when the v4.0
vector is base-only (the common case for OSV records), so default output is
unchanged. Only v4.0 carries a Supplemental Metric Group; v3 and v2 findings
never have a `cvss_supplemental` key.

All of these fields flow through every output format: top-level keys in `json`,
bullets in `h1md`, and `result.properties` entries in `sarif`.

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
  "cvss_score": 6.1,
  "cvss_version": "3.x",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
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
| Azure | Storage Account key (`AccountKey=…==`, `critical`) |
| AI / ML | OpenAI API key (`sk-…T3BlbkFJ…`), Anthropic API key (`sk-ant-api…`), Databricks PAT (`dapi…`, `high`) |
| Secrets mgmt | HashiCorp Vault / HCP service token (`hvs.` / `hvb.`, `critical`) |
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

Alpine's rolling-development branch (**`edge`**) is recognised separately.
OSV.dev keys edge advisories under the distinct ecosystem `Alpine:edge`, so
`casket` detects edge images and queries that channel ahead of the bare-Alpine
fallback. Two on-disk shapes are recognised:

| `etc/alpine-release` | ordered candidates |
|---|---|
| `3.18.4` (a numbered release) | `Alpine:v3.18` → `Alpine` |
| `edge` (the literal edge marker, case-insensitive) | `Alpine:edge` → `Alpine` |
| `3.20.0_alpha20240329` / `_rc1` / `_pre1` / `_git…` / `_beta1` (an in-development build of the next numbered release, shipped via the edge repos) | `Alpine:edge` → `Alpine:v3.20` → `Alpine` |

The edge candidate is queried first for pre-release builds because that is
the channel the image actually ships; the numbered candidate covers the case
where an advisory is filed only against the upcoming stable line. The reported
`detail["ecosystem"]` stays the stable bare `Alpine` tag for output uniformity
in every case — the qualifier is a query-time concern only.

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

The **numeric** base score, the CVSS version, and the source vector are surfaced
on each scorable CVE finding as `cvss_score`, `cvss_version`, and `cvss_vector`
(see [CVE remediation, references & aliases](#cve-remediation-references--aliases)).
The band groups findings into buckets; the numeric score ranks them *within* a
bucket so an operator can triage the most urgent `critical` first, and the vector
shows the attack shape. The three keys are omitted together when no scorable CVSS
vector is present.

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
