# casket — Post-v0.1 Improvement Roadmap

**Generated:** 2026-05-26 by Worker (Rotation 1, research lap)
**Baseline:** v0.1.0 — tarball / podman / remote loading; creds, CVE, misconfig checks; json + h1md output

---

## Methodology

This roadmap was produced by:
1. Full read of the v0.1 codebase (all source, tests, fixtures, ruledata)
2. Research into the 2025/2026 container scanning landscape (Trivy, Grype, TruffleHog, Gitleaks)
3. Analysis of gaps between casket's current capability and what practitioners expect
4. Ranking by: signal-to-noise improvement × implementation complexity (favouring high signal, low complexity)

Each item is ONE focused deliverable — the Phase 2 lap model. Items are ranked 1–7; do them in order.

---

## Item 1 — Alpine APK package extraction (CVE coverage parity)

**Priority: CRITICAL. Do first.**

### What
Add Alpine Linux package extraction to the CVE check. Currently `casket` only reads:
- PyPI: `*.dist-info/METADATA` and `*.egg-info/PKG-INFO`
- Debian: `var/lib/dpkg/status`

Alpine-based images (which represent a large fraction of production container images — `python:3.x-alpine`, `nginx:alpine`, all distroless successors) are invisible to the CVE check today. An Alpine image scanned by casket returns zero CVE findings regardless of how old its packages are.

### How
Parse `/lib/apk/db/installed` (the Alpine installed package database). It is a **plaintext, uncompressed** key-value file in APKINDEX format. Each package stanza looks like:

```
P:musl
V:1.2.3-r4
T:the musl c library
U:https://musl.libc.org/
...
```

Fields of interest: `P` (package name), `V` (version). Split on blank lines to get stanzas.

OSV ecosystem name for Alpine: `"Alpine"`. Confirm against osv.dev's ecosystem list before shipping.

### Effort estimate
~1 day. No new dependencies. Same pattern as `_parse_dpkg_status`. Add:
- `_parse_apk_installed(text)` function in `casket/checks/cves.py`
- Path constant `lib/apk/db/installed`
- Test fixture: a layer tar with a hand-rolled `lib/apk/db/installed` stanza
- Entry in `osv-seed.json` for a known-vulnerable Alpine package (e.g. `musl` or `busybox`)

### Rationale
The container scanning landscape in 2026 treats Alpine CVE coverage as table stakes. Trivy and Grype both cover it. Without it, casket is blind to the most commonly used minimal base image. This is the highest-value CVE coverage gap.

---

## Item 2 — SARIF 2.1.0 output format

**Priority: HIGH. Do second.**

**STATUS: ✅ IMPLEMENTED (Phase 2, Rotation 3).** `--format sarif` is wired into
`cli.py` and emitted by `_render_sarif()` in `casket/findings.py`. Produces a
valid SARIF 2.1.0 document: one `rule` per distinct finding type (deduped by a
`<category>/<slug>` id), one `result` per finding, severity → level mapping
(CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`), and
`artifactLocation.uri` locations with image/layer provenance in `properties`.
Zero new dependencies (stdlib `json`). Covered by `tests/test_sarif.py` (11
structural tests) plus an E2E case in `tests/test_cli_e2e.py`.

### What
Add `--format sarif` output. SARIF (Static Analysis Results Interchange Format) is the OASIS standard for security tool output and the native format for GitHub Advanced Security's Code Scanning. Trivy and Grype both output SARIF; casket's absence of it means it cannot be dropped into a standard GitHub Actions workflow and have findings appear in the Security tab.

### How
SARIF 2.1.0 is pure JSON. A minimum-viable structure:

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "casket",
        "version": "0.1.0",
        "informationUri": "https://github.com/bugsyhewitt/casket",
        "rules": [...]
      }
    },
    "results": [...]
  }]
}
```

Each finding maps to a `result` with:
- `ruleId`: the finding's `rule` field (for creds/misconfig) or `cve_id` (for CVE)
- `message.text`: the finding `title`
- `level`: map `critical/high` → `"error"`, `medium` → `"warning"`, `low/info` → `"note"`
- `locations[0].physicalLocation.artifactLocation.uri`: `path_in_layer`
- `properties.security-severity`: CVSS-like float (critical=9.5, high=7.5, medium=5.0, low=2.0, info=0.0)

Rules array is deduplicated by `ruleId`; each rule carries a `shortDescription.text` from the finding's title.

The `artifactLocation.uri` for misconfig findings (which have `<image config>` as path) should use a synthetic URI like `oci://image-config`.

### Effort estimate
~1 day. New `_render_sarif()` in `casket/findings.py`. Add `sarif` to the `--format` choices in `cli.py`. Tests: verify JSON is valid SARIF shape (schema keys present, `results` length matches findings). No new dependencies — stdlib `json` only.

### Rationale
SARIF is the CI integration lingua franca. Every team with a GitHub Actions pipeline that uploads scan results uses it. Not having it is a friction point that causes casket to be skipped in favor of Trivy. This is a one-day, zero-dependency win that makes casket usable in the most common CI workflow.

---

## Item 3 — Entropy-based credential detection

**Priority: HIGH. Do third.**

### What
Add high-entropy string detection to the creds check as a complement to the existing regex patterns. The current rule set has 4 regex patterns (AWS key, AWS ID, generic API token, private key block). Tools like TruffleHog use two-phase detection: regex patterns first, then entropy analysis for tokens/keys that don't match known formats.

### How
Shannon entropy is straightforward to compute:
```python
import math
from collections import Counter

def _shannon_entropy(s: str, charset: str) -> float:
    if not s:
        return 0.0
    chars = [c for c in s if c in charset]
    if not chars:
        return 0.0
    total = len(chars)
    return -sum((c / total) * math.log2(c / total) for c in Counter(chars).values())
```

Strategy: within a text file, scan for runs of base64-alphabet characters (`[A-Za-z0-9+/=]`) longer than 20 chars. If Shannon entropy > 4.5 bits/char, emit a `high-entropy-string` finding with severity `medium`. Emit the first 8 characters of the matched string (enough for human triage, not enough to leak the full secret).

Add a new rule `id: high_entropy_string` to `creds.yaml` with a flag `kind: entropy` (as opposed to `kind: regex`). The `creds.run()` function checks for `kind` and dispatches accordingly.

Optionally: scan `var/log/` paths with lower entropy threshold (4.0) since logs tend to contain pasted credentials with slightly lower entropy.

### Effort estimate
~1.5 days (entropy logic + false-positive tuning against the existing fixtures). No new dependencies. Tests: craft a layer containing a random 40-char base64 string and verify it fires; verify normal prose does not fire.

### Rationale
TruffleHog has 800+ patterns plus entropy. casket's 4 regex patterns will miss any token format not in the ruleset — internal tokens, custom service keys, database connection strings. Entropy detection is the "catch everything else" layer. Medium severity is appropriate (some false positives expected; operator reviews).

---

## Item 4 — RPM package extraction (RHEL/CentOS/Amazon Linux CVE coverage)

**Priority: MEDIUM. Do fourth.**

**STATUS: ✅ IMPLEMENTED (Phase 2, Rotation 6).** The CVE check now extracts
RPM packages from the modern SQLite rpmdb (`var/lib/rpm/rpmdb.sqlite`; RHEL 9+,
Fedora, Amazon Linux 2023). `_parse_rpmdb_sqlite()` in `casket/checks/cves.py`
spills the blob to a private tempfile, opens it read-only with stdlib
`sqlite3`, and reads each binary RPM *header* blob from the `Packages` table;
`_parse_rpm_header()` decodes the header's index/data-store format with stdlib
`struct` to pull NAME/VERSION/RELEASE/EPOCH/ARCH (zero new dependencies). Full
EVR strings (`epoch:version-release`) are composed via `_rpm_evr()`. OSV
ecosystem tag: `"Red Hat"` (bare, for deterministic offline seed/cache
resolution, mirroring the Alpine decision). The legacy Berkeley DB
`var/lib/rpm/Packages` is skipped silently (no finding, no crash) — BDB parsing
remains out of scope. Covered by 8 new tests in `tests/test_checks.py`
(header parse, malformed-blob/non-sqlite safety, EVR composition, vulnerable +
clean + legacy fixture E2E) with `rpm-image` / `rpm-clean-image` /
`rpm-legacy-image` fixtures and a `Red Hat|openssl|1:3.0.7-6.el9` →
CVE-2023-0464 seed entry.

### What
Add RPM-based package extraction. RHEL, CentOS, Rocky Linux, AlmaLinux, Amazon Linux, and Fedora images all use RPM. Together with Alpine (item 1), adding RPM coverage means casket handles the three major OS package ecosystems (Debian/Ubuntu already done, Alpine in item 1, RPM here).

### How
The RPM situation is more complex than dpkg or apk:
- Modern systems (RHEL 9+, Fedora): `/var/lib/rpm/rpmdb.sqlite` — SQLite database. Python can read it with `sqlite3` (stdlib).
- Older systems (RHEL 7/8, CentOS 7): `/var/lib/rpm/Packages` — Berkeley DB format. **No stdlib parser.** Reading this requires the `rpm` Python bindings (`python3-rpm`), which is a system package, or reading the BDB wire format directly.

**Decision:** Support the SQLite path only (RHEL 9+, Fedora, modern Amazon Linux 2023). Skip BDB silently. The SQLite path is readable with `sqlite3` (stdlib). Query: `SELECT name, version, release, arch FROM Packages`. OSV ecosystem: `"Red Hat"` for RHEL-derived; check osv.dev ecosystem list.

Fallback: if `rpmdb.sqlite` is not present but a `Packages` file is, log a debug-level warning (no finding, no error). Never crash on a missing or unreadable RPM database.

### Effort estimate
~1.5 days. Careful handling of the SQLite-in-tarball case (the DB is a file inside a layer tar — need to extract it to a tempfile before opening with sqlite3). Add tests.

### Rationale
RHEL-family images are common in enterprise environments. Without RPM coverage, casket is incomplete for any org running CentOS/Rocky/RHEL-based images in production.

---

## Item 5 — Registry authentication (bearer token negotiation)

**Priority: MEDIUM. Do fifth.**

**STATUS: ✅ IMPLEMENTED (Phase 2, Rotation 5).** `remote_mode.py` now performs
the OCI Distribution Spec bearer-token challenge-response flow: on a `401
WWW-Authenticate: Bearer realm=...,service=...,scope=...` it parses the
challenge (`parse_www_authenticate`, quote- and comma-aware), fetches a token
from the realm (`_negotiate_token`, optional HTTP Basic creds), and retries the
request, reusing the acquired `Authorization` header for subsequent
manifest/blob fetches. New CLI flags `--token`, `--registry-user`,
`--registry-password` plus `CASKET_REGISTRY_USER` / `CASKET_REGISTRY_PASSWORD`
env vars (CLI wins; env preferred for CI). Credentials are never logged. Zero
new dependencies (httpx already present). Covered by 6 new tests in
`tests/test_remote_mode.py` (challenge parsing, negotiation with/without creds,
token-less realm failure path) against a fixture registry that 401s and issues
tokens. AWS ECR CLI integration intentionally deferred (documented in README).

### What
The current `remote` mode only supports a static `--token` bearer token passed as a CLI flag. Real registries (Docker Hub, GitHub Container Registry, AWS ECR, Azure ACR) issue tokens via a challenge-response flow: the client hits `/v2/`, receives a `401 WWW-Authenticate: Bearer realm=...` response, then fetches a token from the realm URL and retries with `Authorization: Bearer <token>`.

Without this, `--mode remote` only works against private internal registries that accept pre-issued tokens or no auth — it fails on Docker Hub, GHCR, ECR, etc.

### How
Implement the OCI Distribution Spec bearer token flow in `remote_mode.py`:
1. On `401` response with `WWW-Authenticate: Bearer realm=<url>,service=<svc>,scope=<scope>`, extract `realm`, `service`, `scope`
2. GET `{realm}?service={service}&scope={scope}` (with optional Basic Auth credentials if `--registry-user`/`--registry-password` CLI flags are provided)
3. Parse `token` (or `access_token`) from JSON response
4. Retry original request with `Authorization: Bearer {token}`

Add CLI flags: `--registry-user` and `--registry-password` (or environment variables `CASKET_REGISTRY_USER` / `CASKET_REGISTRY_PASSWORD`). Prefer env vars for CI safety.

For AWS ECR: the token endpoint uses `Authorization: Basic base64(AWS:<ecr-token>)` from `aws ecr get-login-password` — document this but don't implement the AWS CLI integration in this item.

### Effort estimate
~2 days. httpx already in the dependency set. Tests: mock the challenge-response flow in the fixture registry server (extend `test_remote_mode.py`). Sensitive: never log credentials.

### Rationale
Without bearer token negotiation, `--mode remote` is unusable against public registries. Docker Hub requires it. GHCR requires it. This is the gap that makes casket look broken to anyone who tries `--mode remote` against a real registry.

---

## Item 6 — Expanded credential ruleset (10 → 25+ patterns)

**Priority: MEDIUM. Do sixth.**

### What
The current `creds.yaml` has 4 rules. TruffleHog ships 800+; Gitleaks ships 160+. casket's value prop is "high signal, low noise" — but 4 patterns misses major real-world credential types that are unambiguous when matched.

Candidates to add (all high-precision, no entropy needed):

| ID | Title | Pattern basis |
|---|---|---|
| `github_pat` | GitHub Personal Access Token | `ghp_[A-Za-z0-9]{36}` |
| `github_oauth` | GitHub OAuth Token | `gho_[A-Za-z0-9]{36}` |
| `github_actions_token` | GitHub Actions Token | `ghs_[A-Za-z0-9]{36}` |
| `slack_token` | Slack API token | `xox[baprs]-[0-9A-Za-z\-]{10,}` |
| `stripe_secret_key` | Stripe secret key | `sk_live_[0-9a-zA-Z]{24,}` |
| `stripe_restricted_key` | Stripe restricted key | `rk_live_[0-9a-zA-Z]{24,}` |
| `gcp_service_account_key` | GCP service account key (JSON) | `"type":\s*"service_account"` |
| `sendgrid_api_key` | SendGrid API key | `SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}` |
| `npm_token` | npm automation token | `npm_[A-Za-z0-9]{36}` |
| `docker_hub_pat` | Docker Hub PAT | `dckr_pat_[A-Za-z0-9_\-]{27}` |
| `jwt_token` | JWT (header.payload.sig) | `eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+` |
| `heroku_api_key` | Heroku API key | `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` (context-guarded) |
| `mailchimp_api_key` | Mailchimp API key | `[0-9a-f]{32}-us[0-9]{1,2}` |
| `twilio_account_sid` | Twilio Account SID | `AC[0-9a-f]{32}` |
| `twilio_auth_token` | Twilio Auth Token | `SK[0-9a-f]{32}` (paired with context) |

All of these have structural prefixes or sufficient length to keep false positive rates negligible. No entropy needed.

### Effort estimate
~1 day. Add to `creds.yaml`, add test cases in `test_checks.py` or a new `test_creds_rules.py`. Add a fixture layer with one each of the new patterns.

### Rationale
A creds scanner with 4 patterns feels like a toy. Adding 15 well-known high-precision patterns covers the real-world tokens teams accidentally bake into images. Each pattern added increases the tool's practical value without adding false positives (all are structurally distinct).

---

## Item 7 — Layered diff mode (show which layer introduced each package/issue)

**Priority: LOW-MEDIUM. Do last.**

**STATUS: ✅ IMPLEMENTED (Phase 2, Rotation 8).** Findings are now annotated
with `detail["layer_command"]` — the Dockerfile instruction that introduced the
finding's layer. `Image.layer_command_map()` in `casket/oci.py` builds a
`{layer_digest: created_by}` map by aligning the filesystem-bearing OCI
`history` entries with `image.layers` positionally; metadata-only steps
(`empty_layer: true`, e.g. `ENV`/`WORKDIR`/`CMD`) are skipped per the image
spec. `scanner.run_checks()` attaches the command to each finding whose
`layer_sha` resolves in the map; config-derived misconfig findings (synthetic
config digest) and history-less images are left unannotated, never
mis-attributed, never crashing. The field surfaces in all three formats for
free (json flatten / h1md detail bullet / sarif properties). Zero new
dependencies. Covered by 9 new tests in `tests/test_layer_command.py`
(map construction + empty/short-history safety + per-layer correctness +
misconfig exclusion + json/h1md/sarif surfacing) against a new `history-image`
fixture with an intervening `empty_layer` ENV step.

### What
casket already tracks `layer_sha` per finding. But operators scanning multi-layer images want to know *which Dockerfile instruction* introduced a vulnerability — not just which SHA. Currently the `history` field on the image config (`image.history`) maps each layer to its `created_by` command (e.g. `RUN apt-get install -y openssl`), but this is never surfaced in findings output.

### How
In `findings.py`'s `render()` function (and in the `Finding` dataclass), optionally include the `created_by` history entry for the matched layer SHA when the image was loaded with history available.

In `scanner.py`'s `run_checks()`, build a `layer_sha → history_entry` map from `image.history` and `image.layers` (the list is positionally aligned), and attach it to each finding via `detail["layer_command"]`.

For json output: add `"layer_command"` key. For h1md: add a `**command:**` bullet. For SARIF (item 2): add to `properties`.

### Effort estimate
~0.5 days. Mostly wiring. Tests: verify that the history entry appears in JSON output for a multi-layer fixture.

### Rationale
This makes findings actionable: instead of "layer sha256:abc123 has a leaked key", the output reads "the RUN command `COPY .env /app/.env` introduced this finding". Operators can then fix the Dockerfile directly. Low implementation cost, high operator value.

---

## Summary table

| # | Item | Effort | Impact | Priority |
|---|---|---|---|---|
| 1 | Alpine APK package extraction | 1 day | Critical — closes Alpine CVE blindspot | **CRITICAL** |
| 2 | SARIF 2.1.0 output format | 1 day | High — enables GitHub Advanced Security CI | **HIGH** |
| 3 | Entropy-based credential detection | 1.5 days | High — catches unknown token formats | **HIGH** |
| 4 | RPM package extraction | 1.5 days | Medium — RHEL/Amazon Linux CVE coverage | **MEDIUM** |
| 5 | Registry authentication (bearer token flow) | 2 days | Medium — `--mode remote` works on real registries | **MEDIUM** |
| 6 | Expanded credential ruleset (4 → 19 patterns) | 1 day | Medium — practical coverage for real teams | **MEDIUM** |
| 7 | Layered diff mode (history command attribution) | 0.5 days | Low-Medium — operator ergonomics | ✅ DONE |

**Total estimated effort: ~8.5 days** of focused implementation, spread across Phase 2 laps.

All seven original items shipped by Rotation 8. Subsequent rotations extend the
roadmap below.

---

## Extended directions (post-Item-7)

The original 1–7 roadmap is fully shipped. These are the next-highest-value
improvements identified by later rotations after re-assessing the codebase.

### Item 8 — Alpine release-qualified OSV resolution

**Priority: HIGH. ✅ IMPLEMENTED (Phase 2, Rotation 10).**

**The gap.** Item 1 (Rotation 2) added Alpine package extraction and tagged
packages with the bare ecosystem `"Alpine"`. That resolves fine against the
bundled seed DB and the on-disk cache (both keyed on bare `Alpine`), but a
*live* OSV.dev query for ecosystem `Alpine` returns nothing — OSV keys Alpine
vulns under release-qualified ecosystems like `Alpine:v3.18`. So casket's
flagship Alpine CVE coverage was effectively **seed-only** against the real
API: any Alpine package not hand-seeded was invisible. The Rotation 2 worker
explicitly flagged this as a deferred follow-up.

**What shipped.** casket now reads `etc/alpine-release` (a one-line plaintext
version, e.g. `3.18.4`) from the image, derives the release-qualified ecosystem
`Alpine:vMAJOR.MINOR` (`Alpine:v3.18`), and queries that *first*, falling back
to bare `Alpine`. Implementation:

- `_parse_alpine_release(text)` in `casket/checks/cves.py` extracts MAJOR.MINOR
  from the release line (tolerates `3.18`, `3.18.4`, `3.18.0_alpha…`) and
  returns the OSV qualifier, or `None` on garbage.
- `_detect_alpine_ecosystem(image)` is an **image-level** scan:
  `etc/alpine-release` and `lib/apk/db/installed` frequently live in different
  layers, so detection scans all layers and the first parseable release wins.
- `OSVClient.query_ecosystems(ecosystems, package, version)` in
  `casket/osv.py` tries an ordered candidate list and returns the first
  non-empty result (skips falsy/`None` candidates, dedupes). `cves.run()` calls
  it for Alpine packages with `[Alpine:v3.18, Alpine]`.
- The reported `detail["ecosystem"]` stays the bare `"Alpine"` tag for output
  uniformity; the qualifier is a query-time concern only.

Zero new dependencies. Covered by 9 new tests (release parsing, cross-layer
detection, the candidate-ordering/fallback/dedupe logic in `query_ecosystems`,
plus an E2E test proving the live query path sends `Alpine:v3.18`) against a
new `alpine-release-image` fixture that places `etc/alpine-release` in a
separate layer from the apk db.

**Why this was the pick.** It's a correctness fix to the suite's *most
common base image* (`*-alpine`) coverage — the one POST_V01 ranked CRITICAL —
that was silently degraded to seed-only against the live API. High value,
low complexity, zero new dependencies, no scope creep.

### Already-shipped beyond the table

- **`--fail-on` severity gate** (Rotation 9): CI exit-code control so a single
  INFO finding doesn't break a build the way a leaked AWS key does. See
  `exit_code()` / `FAIL_ON_CHOICES` in `casket/scanner.py`.

### Item 9 — Debian/Ubuntu release-qualified OSV resolution

**Priority: HIGH. ✅ IMPLEMENTED (Phase 2, Rotation 11).**

The same gap Item 8 fixed for Alpine existed for Debian: dpkg packages were
tagged with the bare ecosystem `"Debian"`, but OSV.dev keys Debian vulns under
the major-release-qualified ecosystem `Debian:12`. So a *live* OSV.dev query for
bare `Debian` returned nothing — Debian/Ubuntu CVE coverage was effectively
seed-only against the real API.

**What shipped.** casket now reads the Debian release from `etc/debian_version`
(a one-line version like `12.4`), falling back to the `VERSION_ID` field of
`etc/os-release` (Ubuntu and `*-slim` images that ship no `etc/debian_version`),
derives the release-qualified ecosystem `Debian:MAJOR` (`Debian:12`), and
queries that *first* via the existing `OSVClient.query_ecosystems`, falling back
to bare `Debian` (seed DB / warm cache). Implementation, mirroring the Alpine
pattern exactly:

- `_parse_debian_version(text)` extracts MAJOR from `etc/debian_version`
  (ignores non-numeric testing codenames like `bookworm/sid`).
- `_parse_os_release_debian(text)` extracts MAJOR from an `os-release`
  `VERSION_ID="12"` line (quote-tolerant; Ubuntu's `22.04` → `Debian:22`).
- `_detect_debian_ecosystem(image)` is an image-level scan (release marker and
  dpkg db often live in different layers); `etc/debian_version` is preferred,
  with `etc/os-release` `VERSION_ID` as the fallback.
- `cves.run()` calls `query_ecosystems([debian_ecosystem, "Debian"], ...)` for
  Debian packages. The reported `detail["ecosystem"]` stays bare `"Debian"` for
  output uniformity; the qualifier is a query-time concern only.

Zero new dependencies. Covered by 11 new tests in `tests/test_checks.py`
(version + os-release parsing, codename/missing-field None paths, cross-layer
detection, os-release fallback detection, the release-qualified query path
proven by seeding *only* under `Debian:12`, the os-release-derived variant, and
the bare-`Debian` seed-DB fallback chain) against new `debian-release-image`
(release marker in a separate layer from the dpkg db) and
`debian-osrelease-image` (os-release-only) fixtures, plus a bare
`Debian|openssl|3.0.11-1~deb12u1` → CVE-2023-5678 seed entry.

### Item 10 — CVSS `security-severity` in SARIF output

**Priority: HIGH. ✅ IMPLEMENTED (Phase 2, Rotation 12).**

Item 2 (SARIF) originally specified a `properties.security-severity` float, but
the shipped emitter never produced it: rules and results carried only the
qualitative `severity` string. GitHub code-scanning sorts and gates findings by
the CVSS-like `security-severity` float (a *string* per GitHub's ingest
contract), so without it casket's SARIF appeared in the Security tab but could
not be ranked or threshold-gated by severity — every finding looked equally
urgent.

**What shipped.** `_render_sarif()` in `casket/findings.py` now emits
`properties.security-severity` on both every `reportingDescriptor` (rule, where
GitHub reads it) and every `result`. The float follows the Item 2 table:
CRITICAL=`"9.5"`, HIGH=`"7.5"`, MEDIUM=`"5.0"`, LOW=`"2.0"`, INFO=`"0.0"`,
via the `_SEVERITY_TO_SECURITY_SEVERITY` map and `_security_severity()` helper;
an out-of-vocabulary severity defaults to a safe mid-range `"5.0"` and never
crashes. Zero new dependencies (stdlib `json`). Covered by 13 new tests in
`tests/test_sarif.py` (per-severity rule + result floats, string-type/range
contract, severity-ordering monotonicity across a mixed document, and the
unknown-severity default path).

### Item 11 — CVSS-derived CVE severity from the OSV-standard `severity` array

**Priority: HIGH. ✅ IMPLEMENTED (Phase 2, Rotation 14).**

Items 2/10 made SARIF carry a `security-severity` float and `--fail-on`
(Rotation 9) gate by severity — but both are only as good as the qualitative
`severity` string casket assigns each CVE. That string came solely from
`_severity_from_osv()` reading `database_specific.severity`, an explicit label
that **only PyPI/GHSA records reliably carry**. The OSV records for the OS
ecosystems casket spent Rotations 1/6/8/11 wiring up — Debian, Alpine, Red Hat
— almost universally carry severity as a CVSS *vector* in the OSV-standard
top-level `severity` array and have **no** `database_specific.severity` at all.
So every OS-package CVE silently defaulted to `high`: a low-severity Debian CVE
and a critical one looked identical, and `--fail-on critical` / SARIF severity
sort were effectively blind for the exact package families casket targets.

**What shipped.** `_severity_from_osv()` in `casket/checks/cves.py` now resolves
severity most-authoritative-first: (1) `database_specific.severity` when it's a
recognised label (unchanged, still wins); (2) the OSV-standard `severity` array
— `_severity_from_cvss_array()` picks the newest usable CVSS version present
(V4 > V3 > V2), `_cvss_base_score()` recomputes the **CVSS v3.x base score**
from the vector with the standard formula (scope-aware impact/exploitability,
CVSS `Roundup`), and `_cvss_band()` buckets it into casket's vocabulary
(`9.0+`→critical, `7.0+`→high, `4.0+`→medium, else low); (3) the prior `high`
default, untouched, for unparseable/absent signal. CVSS v2/v4 vectors (different
formulae) are skipped, not mis-scored, so a lower-ranked usable V3 vector still
wins. Base scores were validated against the FIRST.org v3.1 calculator. Zero new
dependencies (stdlib `re` only). Covered by **11 new tests** in
`tests/test_checks.py` (FIRST.org reference scores, band ranges, incomplete-vector
None path, array parsing + version preference + non-list/empty handling,
db_specific-wins resolution order, the new CVSS fallback, the
medium-no-longer-misreported-as-high regression, the conservative default, and
an end-to-end seeded CVE proving a CVSS-5.4 record now reports `medium`).

**Why this was the pick.** It's a correctness fix that makes the two severity-
consuming features casket already shipped (`--fail-on`, SARIF `security-severity`)
actually trustworthy for OS-package CVEs — the dominant finding type for the
Debian/Alpine/Red Hat images casket targets. High value, low complexity, zero new
dependencies, no scope creep.

### Candidate next items (not yet done)

- **Alpine `edge` handling** — `etc/alpine-release` on edge images is non-numeric;
  OSV has no `Alpine:edge`. Currently falls back to bare `Alpine` (fine, but
  could log a note).

---

## What is NOT on this list (and why)

- **Docker daemon support** — explicitly out of scope, violates the daemonless niche
- **Kubernetes manifest scanning** — different problem domain, adds scope creep
- **Sigstore signature verification** — valuable but requires new dependencies and significant complexity
- **Full SBOM generation (CycloneDX/SPDX)** — higher complexity, makes casket a different tool; the CVE check already extracts a partial package inventory; full SBOM is a Phase 3 decision
- **Live secret validation** (TruffleHog-style API calls to check if a key is active) — adds network side effects, raises ethical complexity, out of the defensive-tool model
- **Custom rule DSLs** — explicitly excluded in v0.1 guardrails; YAML-based rules already support custom regexes
- **Multi-arch manifest selection** — useful but not blocking; current behavior (first manifest) works for most cases
