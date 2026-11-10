# Distribution security boundary

The only first-release applications are Diagnostic Gateway 0.6.1 and Deployment
Simulator 0.1.1. Their profiles refuse real mode, credentials are discarded before
exec, the runtime is unprivileged and seccomp irreversibly denies sockets and
network io_uring operations. Failure to install the filter refuses startup. This
filters shipped processes and descendants; it does not prevent an administrator
from invoking arbitrary code with Docker exec. ARM64 must be tested natively
before claiming Green compatibility beyond image construction.

No Supervisor/HA auth, mounts of production data, host namespace, port, VPN or
physical command is granted. A simulation can create synthetic files on `/tmp`
only. No catalogue tool calls Home Assistant or performs an installation/update.

## What integrity means here

Git review authenticates the public source commit. A closed inventory checks
source hashes and rejects extra files, links, unknown permissions and common
credential signatures. The private export additionally excludes private context
and supplies a review report **outside** the public proposal. Automated scanning
cannot prove absence of every secret or private text; human review of all public
files, dependencies and image layers is required before first publication.

CI hashes tested Docker archives, verifies image identities, revision/version/arch
labels and publishes only those archives after required review. It also inspects
every `/app` file in saved layers without extracting or executing them, compares
their bytes to the closed source inventory, and rejects extra environment/labels.
Published images will carry
GitHub OIDC build provenance. A separate promotion verifies signer workflow,
public source commit, anonymous pull and the exact registry digests. Docker pulls
verify content-addressed layers over HTTPS.

**Home Assistant does not enforce these attestations or our release record.**
Its `image` field accepts a name, with `version` as tag, not our digest pin.
Compromised repository/registry administration could retarget a tag after review.
Our tooling refuses replacing an existing tag, but this is not registry-enforced
immutability. Protect accounts, environments and package write permissions.
This residual trust decision must be accepted before publication. No signature
is checked locally by Green in this architecture; adding a privileged verifier
would change the isolation and is deliberately excluded.

A public repository discloses the generic source code and any future commit
history. GHCR layers and attestations are also public. Do not include internal
hostnames, entity names, private repository URLs/commits, logs, exports, private
keys or credentials. Do not mirror any private Git history or build directly
from a private checkout in the public publishing job. Resolve ownership/licensing
of the original code and retain dependency notices before public release.

No `pull_request_target`, repository dispatch, scheduled publication, `latest`
tag, automatic promotion, installation or production update is provided.

## Security remediation — 2026-11-10

The initial Grype audit of commit `85fe37a` found **152 package/advisory
matches per image** (9 Critical, 64 High, 58 Medium, 20 Low, 1 Negligible).
The same set occurred in all four images: 608 matches are not 608 distinct
vulnerabilities. There were 111 literal advisory identifiers (105 CVE,
6 GHSA); aliases are not assumed independent or falsely classified as fixed.
OpenSSL findings repeat for libcrypto/libssl and BusyBox for its split packages.
59 of 73 High/Critical package matches had a recorded fix; 14 High matches
(SQLite and OpenSSL) did not in that database. No exploit was demonstrated and
no advisory has been waived as a false positive.

The base is updated to official **Python 3.15.2 / Alpine 3.24**, pinned by
multiarchitecture index digest in `DEPENDENCIES.json`, with upstream build
commit and both architecture manifests. Python 3.12.16 was tested first but still matched advisories whose safe stable
fixes are on newer Python branches; 3.14.10 eliminated all High/Critical findings but retained
CVE-2025-15367, fixed in the maintained stable 3.15.2 release now tested on both architectures. No moving
`apk upgrade`, third-party base or unpinned dependency installer is added.
Signed official zlib 1.4-r0 APKs are checksum-pinned separately for both
architectures and verified against the pinned base architecture-specific keys.
Only these fixed local APKs are installed, with networking disabled during RUN.
The unused SQLite library and its Python modules are removed through the package
manager and filesystem; pip, its scripts and ensurepip wheels are also removed.
Their imports must fail in runtime tests; no scanner metadata is hidden or
rewritten. Simulations use JSON files and do not need SQLite or package installers.
Python SSL and compression remain tested. The original base layers still contain
superseded bytes, as with ordinary layered image updates; only the merged runtime
is executed and audited. Do not treat deletion as confidential data erasure.
The base's PSF/system-package licences still apply; vendored PyYAML 6.0.3
and its MIT licence are unchanged and hash checked.

The Docker healthcheck now invokes the same bootstrap as PID 1. A short root
bootstrap reads Supervisor's potentially root-only options, locks networking,
then drops supplementary groups and UID/GID to 65532 and **execs with a clean
environment**. The actual probe checks its own UID/GID, all capability sets,
NoNewPrivs, seccomp and initial process environment; direct root/dirty-env
invocation fails. Heartbeat reads use descriptor-relative NOFOLLOW, regular
single-link files, a 4096-byte bound and age 0–30 seconds. Stale/future,
oversized, linked and unsafe-flags files are regression tested on both native
architectures. Docker has no non-root USER declaration because the options
bootstrap needs that brief root phase; this is a documented residual boundary,
not a claim that no process ever starts as root.

All vulnerability findings remain reported. High/Critical findings fail the
required `offline-build` gate, including unfixed findings. There are **no
exemptions** and no `ignore-unfixed` flag. Fresh Grype and native results must
be reviewed for the exact final PR revision before publication. No image,
store metadata or Home Assistant installation is published by these tests.

The publisher additionally refuses environments that allow administrator bypass.
The GitHub environment/branch settings API is unavailable in this Codex task
(`Forbidden`); repository-side checks fail closed, but the actual settings must
be independently reviewed before any publication. QEMU is checksum-pinned and
used only for cross-building on disposable AMD64 CI runners. ARM64 runtime tests
remain on a native `ubuntu-24.04-arm` runner, without emulation.

## Complete baseline triage (152 package/advisory matches per image)

Baseline: commit `85fe37a`, run [42810893283](https://github.com/quentinheylens/Maison-apps/actions/runs/42810893283),
Grype 0.121.3, database schema v6.1.10, built 2026-11-10T06:21:20Z.
Each row below occurred in all four images; a split library package is kept as
its own row rather than silently counted as another independent vulnerability.
Fix versions are **scanner-reported candidates**, not an instruction to select
a prerelease or install a version from an incompatible distribution. An empty
fix list means unknown to that database, not proof that no upstream fix exists.

Runtime exposure: there is no listener, external input, HA mount or credential
in the simulator runtime. Network syscalls are denied, UID/GID is 65532 and
capabilities are zero. No exploitation test or authoritative KEV/EPSS enrichment
was available; **known exploitation remains unknown for every listed advisory**.
Lower reachability does not establish a false positive. No row is suppressed.
SQLite (JSON-only simulations) and pip/ensurepip (immutable applications) are
removed as unused functionality, with negative runtime import tests. Libraries
and interpreter actually used are updated, with native tests of SSL and zlib.

| Package | Baseline version | C / H / M / L / N | Matches with a recorded fix | Runtime change |
| --- | --- | --- | --- | --- |
| busybox | 1.37.0-r20 | 0 / 0 / 1 / 0 / 0 | 0 / 1 | 1.37.0-r31; review residual advisory |
| busybox-binsh | 1.37.0-r20 | 0 / 0 / 1 / 0 / 0 | 0 / 1 | 1.37.0-r31; same BusyBox advisory |
| libcrypto3 | 3.5.6-r0 | 3 / 19 / 10 / 6 / 0 | 25 / 38 | OpenSSL 3.5.9-r0 |
| libssl3 | 3.5.6-r0 | 3 / 19 / 10 / 6 / 0 | 25 / 38 | OpenSSL 3.5.9-r0 |
| libuuid | 2.41-r9 | 0 / 6 / 2 / 0 / 0 | 8 / 8 | 2.42.3-r1 |
| musl | 1.2.5-r12 | 0 / 1 / 0 / 0 / 0 | 1 / 1 | 1.2.6-r3 |
| musl-utils | 1.2.5-r12 | 0 / 1 / 0 / 0 / 0 | 1 / 1 | 1.2.6-r3 |
| pip | 25.0.1 | 0 / 0 / 5 / 1 / 0 | 6 / 6 | Removed, including ensurepip wheels |
| python | 3.12.13 | 2 / 11 / 20 / 6 / 1 | 40 / 40 | CPython 3.15.2 |
| sqlite-libs | 3.49.2-r1 | 0 / 6 / 7 / 1 / 0 | 0 / 14 | Removed, including Python extension |
| ssl_client | 1.37.0-r20 | 0 / 0 / 1 / 0 / 0 | 0 / 1 | 1.37.0-r31; same BusyBox advisory |
| xz-libs | 5.8.1-r0 | 0 / 0 / 1 / 0 / 0 | 1 / 1 | 5.8.4-r0 |
| zlib | 1.3.2-r0 | 1 / 1 / 0 / 0 / 0 | 2 / 2 | 1.4-r0, signed/hash-pinned |

The six pip GHSA identifiers may alias CVEs; no unverified alias collapse is used.
The libcrypto/libssl rows refer to the same upstream OpenSSL advisories but to
two shipped packages. BusyBox's three split packages share CVE-2025-60876.
The old unfixed High set comprises six SQLite matches and eight OpenSSL matches,
not Python. Package upgrades can remove matches because of vendor backports or
namespace changes; absence in a fresh scan is not proof of universal immunity.

<details>
<summary>All 152 baseline rows and their recorded fix candidates</summary>

| Advisory | Package | Severity | Baseline version | Recorded fix candidates |
| --- | --- | --- | --- | --- |
| CVE-2025-60876 | busybox | Medium | 1.37.0-r20 | None recorded |
| CVE-2025-60876 | busybox-binsh | Medium | 1.37.0-r20 | None recorded |
| CVE-2026-34182 | libcrypto3 | Critical | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-63073 | libcrypto3 | Critical | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-75803 | libcrypto3 | Critical | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-14456 | libcrypto3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-14457 | libcrypto3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-18798 | libcrypto3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-34180 | libcrypto3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-34181 | libcrypto3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-34183 | libcrypto3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42764 | libcrypto3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-45445 | libcrypto3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-45447 | libcrypto3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-54873 | libcrypto3 | High | 3.5.6-r0 | None recorded |
| CVE-2026-54874 | libcrypto3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-63072 | libcrypto3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-63075 | libcrypto3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-63076 | libcrypto3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-72897 | libcrypto3 | High | 3.5.6-r0 | None recorded |
| CVE-2026-7383 | libcrypto3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-84782 | libcrypto3 | High | 3.5.6-r0 | None recorded |
| CVE-2026-84784 | libcrypto3 | High | 3.5.6-r0 | None recorded |
| CVE-2026-9076 | libcrypto3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-35191 | libcrypto3 | Low | 3.5.6-r0 | None recorded |
| CVE-2026-42768 | libcrypto3 | Low | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42770 | libcrypto3 | Low | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-54872 | libcrypto3 | Low | 3.5.6-r0 | None recorded |
| CVE-2026-54875 | libcrypto3 | Low | 3.5.6-r0 | None recorded |
| CVE-2026-77696 | libcrypto3 | Low | 3.5.6-r0 | None recorded |
| CVE-2026-35189 | libcrypto3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-42766 | libcrypto3 | Medium | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42767 | libcrypto3 | Medium | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42769 | libcrypto3 | Medium | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42772 | libcrypto3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-45446 | libcrypto3 | Medium | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-63074 | libcrypto3 | Medium | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-75804 | libcrypto3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-75805 | libcrypto3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-75806 | libcrypto3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-34182 | libssl3 | Critical | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-63073 | libssl3 | Critical | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-75803 | libssl3 | Critical | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-14456 | libssl3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-14457 | libssl3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-18798 | libssl3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-34180 | libssl3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-34181 | libssl3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-34183 | libssl3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42764 | libssl3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-45445 | libssl3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-45447 | libssl3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-54873 | libssl3 | High | 3.5.6-r0 | None recorded |
| CVE-2026-54874 | libssl3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-63072 | libssl3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-63075 | libssl3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-63076 | libssl3 | High | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-72897 | libssl3 | High | 3.5.6-r0 | None recorded |
| CVE-2026-7383 | libssl3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-84782 | libssl3 | High | 3.5.6-r0 | None recorded |
| CVE-2026-84784 | libssl3 | High | 3.5.6-r0 | None recorded |
| CVE-2026-9076 | libssl3 | High | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-35191 | libssl3 | Low | 3.5.6-r0 | None recorded |
| CVE-2026-42768 | libssl3 | Low | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42770 | libssl3 | Low | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-54872 | libssl3 | Low | 3.5.6-r0 | None recorded |
| CVE-2026-54875 | libssl3 | Low | 3.5.6-r0 | None recorded |
| CVE-2026-77696 | libssl3 | Low | 3.5.6-r0 | None recorded |
| CVE-2026-35189 | libssl3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-42766 | libssl3 | Medium | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42767 | libssl3 | Medium | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42769 | libssl3 | Medium | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-42772 | libssl3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-45446 | libssl3 | Medium | 3.5.6-r0 | 3.5.7-r0 |
| CVE-2026-63074 | libssl3 | Medium | 3.5.6-r0 | 3.5.8-r0 |
| CVE-2026-75804 | libssl3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-75805 | libssl3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-75806 | libssl3 | Medium | 3.5.6-r0 | None recorded |
| CVE-2026-53612 | libuuid | High | 2.41-r9 | 2.41.6-r0 |
| CVE-2026-53613 | libuuid | High | 2.41-r9 | 2.41.6-r0 |
| CVE-2026-53614 | libuuid | High | 2.41-r9 | 2.41.6-r0 |
| CVE-2026-76642 | libuuid | High | 2.41-r9 | 2.41.6-r0 |
| CVE-2026-78408 | libuuid | High | 2.41-r9 | 2.41.6-r1 |
| CVE-2026-78410 | libuuid | High | 2.41-r9 | 2.41.6-r0 |
| CVE-2025-14104 | libuuid | Medium | 2.41-r9 | 2.41.6-r0 |
| CVE-2026-27456 | libuuid | Medium | 2.41-r9 | 2.41.6-r0 |
| CVE-2026-107891 | musl | High | 1.2.5-r12 | 1.2.5-r13 |
| CVE-2026-107891 | musl-utils | High | 1.2.5-r12 | 1.2.5-r13 |
| GHSA-6vgw-5pg2-w6jp | pip | Low | 25.0.1 | 26.0 |
| GHSA-4xh5-x5gv-qwph | pip | Medium | 25.0.1 | 25.3 |
| GHSA-58qw-9mgm-455v | pip | Medium | 25.0.1 | 26.1 |
| GHSA-jp4c-xjxw-mgf9 | pip | Medium | 25.0.1 | 26.1 |
| GHSA-qwm4-qh6w-59xr | pip | Medium | 25.0.1 | 26.2.0 |
| GHSA-wf93-45jw-7689 | pip | Medium | 25.0.1 | 26.1.2 |
| CVE-2026-115557 | python | Critical | 3.12.13 | 3.11.18, 3.12.16, 3.13.18, 3.14.10, 3.15.2, 3.16.0 |
| CVE-2026-19445 | python | Critical | 3.12.13 | 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8, 3.15.0rc3 |
| CVE-2026-11940 | python | High | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.15, 3.14.7, 3.15.0b4 |
| CVE-2026-11972 | python | High | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.15, 3.14.7, 3.15.0b4 |
| CVE-2026-15308 | python | High | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.15, 3.14.7, 3.15.0b4 |
| CVE-2026-19553 | python | High | 3.12.13 | 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8, 3.15.0rc3 |
| CVE-2026-3644 | python | High | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.13, 3.14.4, 3.15.0a8 |
| CVE-2026-4224 | python | High | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.13, 3.14.4, 3.15.0a8 |
| CVE-2026-4786 | python | High | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.14, 3.14.5rc1, 3.15.0b1 |
| CVE-2026-6100 | python | High | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.14, 3.14.5rc1, 3.15.0b1 |
| CVE-2026-7210 | python | High | 3.12.13 | 3.10.22, 3.11.16, 3.12.14, 3.13.14, 3.14.6, 3.15.0b2 |
| CVE-2026-82049 | python | High | 3.12.13 | 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.0b1 |
| CVE-2026-9669 | python | High | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.14, 3.14.6, 3.15.0b3 |
| CVE-2025-13462 | python | Low | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.13, 3.14.4, 3.15.0a8 |
| CVE-2026-103995 | python | Low | 3.12.13 | 3.16.0 |
| CVE-2026-15310 | python | Low | 3.12.13 | 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8, 3.15.0rc2 |
| CVE-2026-18503 | python | Low | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.15, 3.14.7, 3.15.0rc1 |
| CVE-2026-4519 | python | Low | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.13, 3.14.4, 3.15.0a8 |
| CVE-2026-6879 | python | Low | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.15, 3.14.7, 3.15.0rc1 |
| CVE-2025-12781 | python | Medium | 3.12.13 | 3.13.10, 3.14.1, 3.15.0a2 |
| CVE-2025-15366 | python | Medium | 3.12.13 | 3.13.15, 3.14.7, 3.15.0a6 |
| CVE-2025-15367 | python | Medium | 3.12.13 | 3.15.0a6 |
| CVE-2026-0864 | python | Medium | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.15, 3.14.7, 3.15.0b4 |
| CVE-2026-114583 | python | Medium | 3.12.13 | 3.11.18, 3.12.16, 3.13.18, 3.14.10, 3.15.2, 3.16.0 |
| CVE-2026-116566 | python | Medium | 3.12.13 | 3.16.0 |
| CVE-2026-12003 | python | Medium | 3.12.13 | 3.11.16, 3.12.14, 3.13.15, 3.14.7, 3.15.0b3 |
| CVE-2026-12345 | python | Medium | 3.12.13 | 3.12.15, 3.13.18, 3.14.9, 3.15.0rc3 |
| CVE-2026-1502 | python | Medium | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.14, 3.14.5rc1, 3.15.0b1 |
| CVE-2026-15806 | python | Medium | 3.12.13 | 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8, 3.15.0rc2 |
| CVE-2026-17084 | python | Medium | 3.12.13 | 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8, 3.15.0rc2 |
| CVE-2026-19672 | python | Medium | 3.12.13 | 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8, 3.15.0rc2 |
| CVE-2026-2297 | python | Medium | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.13, 3.14.4, 3.15.0a7 |
| CVE-2026-3276 | python | Medium | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.14, 3.14.6, 3.15.0b2 |
| CVE-2026-3446 | python | Medium | 3.12.13 | 3.13.13, 3.14.4, 3.15.0a8 |
| CVE-2026-4360 | python | Medium | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.15, 3.14.7, 3.15.0b4 |
| CVE-2026-6019 | python | Medium | 3.12.13 | 3.13.14, 3.14.5rc1, 3.15.0b1 |
| CVE-2026-7774 | python | Medium | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.14, 3.14.6, 3.15.0b2 |
| CVE-2026-8328 | python | Medium | 3.12.13 | 3.10.21, 3.11.16, 3.12.14, 3.13.14, 3.14.6, 3.15.0b2 |
| CVE-2026-87910 | python | Medium | 3.12.13 | 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.9, 3.15.0rc3 |
| CVE-2026-3479 | python | Negligible | 3.12.13 | 3.13.13, 3.14.4, 3.15.0a8 |
| CVE-2025-70873 | sqlite-libs | High | 3.49.2-r1 | None recorded |
| CVE-2026-11824 | sqlite-libs | High | 3.49.2-r1 | None recorded |
| CVE-2026-119373 | sqlite-libs | High | 3.49.2-r1 | None recorded |
| CVE-2026-119374 | sqlite-libs | High | 3.49.2-r1 | None recorded |
| CVE-2026-119379 | sqlite-libs | High | 3.49.2-r1 | None recorded |
| CVE-2026-119586 | sqlite-libs | High | 3.49.2-r1 | None recorded |
| CVE-2026-119377 | sqlite-libs | Low | 3.49.2-r1 | None recorded |
| CVE-2026-11822 | sqlite-libs | Medium | 3.49.2-r1 | None recorded |
| CVE-2026-119371 | sqlite-libs | Medium | 3.49.2-r1 | None recorded |
| CVE-2026-119372 | sqlite-libs | Medium | 3.49.2-r1 | None recorded |
| CVE-2026-119375 | sqlite-libs | Medium | 3.49.2-r1 | None recorded |
| CVE-2026-119376 | sqlite-libs | Medium | 3.49.2-r1 | None recorded |
| CVE-2026-119378 | sqlite-libs | Medium | 3.49.2-r1 | None recorded |
| CVE-2026-119591 | sqlite-libs | Medium | 3.49.2-r1 | None recorded |
| CVE-2025-60876 | ssl_client | Medium | 1.37.0-r20 | None recorded |
| CVE-2026-34743 | xz-libs | Medium | 5.8.1-r0 | 5.8.3-r0 |
| CVE-2026-4738 | zlib | Critical | 1.3.2-r0 | 1.4-r0 |
| CVE-2026-85091 | zlib | High | 1.3.2-r0 | 1.3.2-r1 |

</details>

## Result and residual-risk decision

Functional source revision: `86a868a4892cfa0c18e7b8497732671ddebcb8e0`.
GitHub's virtual PR merge tested: `60b3baaeff0779630c551388f37965489f96c168`.
This is a test ref, **not** a merge into main or a future release SHA.
[Exact validation run](https://github.com/quentinheylens/Maison-apps/actions/runs/42819918932).
The final review commit also adds Docker-scheduled probe regression coverage and
this report; its own checks must be green on the PR before any release decision.

Grype 0.121.3 with the same valid official database reports, for **each** image:
**0 Critical, 0 High, 4 Medium, 1 Low** (5 matches, down from 152).
Across all four images: 16 Medium and 4 Low matches, representing **three CVEs**.
Explicit vendored PyYAML SBOM: 0 findings. No `ignore-unfixed`, scanner exemptions
or reduced failure threshold were introduced. All High/Critical matches were
removed through updates or removal of unused executable functionality.

Native ARM64 tests passed for both roles on `ubuntu-24.04-arm` (`aarch64`),
including the new healthcheck's own identity/environment and denial tests.
Observed peak RSS: Diagnostic 26,892 KiB, Deployment 26,700 KiB; selftest CPU:
0.4671 / 0.4732 seconds. These are synthetic selftest measurements, not permanent
Green resource guarantees. Tests cap containers at 192 MiB, 0.5 CPU, read-only
rootfs, network namespace none, 16 MiB tmpfs; HA/Supervisor and host mounts remain
absent. No Green installation, HA OS/AppArmor integration or real HA test occurred.

### Remaining findings (all still present in scanner output)

| Advisory | Severity / matches per image | Component | Fix availability | Vector and remaining uncertainty |
| --- | --- | --- | --- | --- |
| CVE-2025-60876 | Medium / 3 | busybox, busybox-binsh, ssl_client 1.37.0-r31 | No fixed version recorded; pinned Alpine stable recipe is already 1.37.0-r31 | BusyBox wget HTTP request-target control characters can inject headers. A public PoC is referenced by the CNA; not executed here. No wget or HTTP client is invoked by these simulators and socket creation is denied. In-the-wild exploitation is **unknown**. The CNA description's version spelling is ambiguous; this is not enough evidence to waive the package findings as false positives. |
| CVE-2026-116566 | Medium / 1; CNA CVSS 4.0 5.3 | CPython 3.15.2, socket.getaddrinfo | Scanner and CNA identify 3.16.0; only 3.16.0a1 is advertised in the official image list at review time, not a stable fix to adopt | NUL bytes can silently truncate host/port values. No caller-provided host/port is accepted in the sealed simulator and socket syscalls are denied. Public vendor patch/issue exist; in-the-wild exploitation and exploitability through this application are **unknown**, not proven impossible. |
| CVE-2026-103995 | Low / 1; CNA CVSS 4.0 2.0 | CPython 3.15.2, http.client | Same stable 3.16.0 boundary; no supported stable update identified | Incorrect HTTP chunk/body integer parsing. There are no HTTP responses consumed by the dormant simulator and no transport activation. Vendor patches exist; known exploitation remains **unknown**. |

CNA records were read from the public CVE List snapshot
`75879ab6287dce1cc946a43bb0e63146e079429e`:
[CVE-2025-60876](https://github.com/CVEProject/cvelistV5/blob/75879ab6287dce1cc946a43bb0e63146e079429e/cves/2025/60xxx/CVE-2025-60876.json),
[CVE-2026-116566](https://github.com/CVEProject/cvelistV5/blob/75879ab6287dce1cc946a43bb0e63146e079429e/cves/2026/116xxx/CVE-2026-116566.json),
[CVE-2026-103995](https://github.com/CVEProject/cvelistV5/blob/75879ab6287dce1cc946a43bb0e63146e079429e/cves/2026/103xxx/CVE-2026-103995.json).
No independent KEV/EPSS lookup or exploit execution was performed. This report
uses scanner severity and reachability evidence, not an unsubstantiated promise
of non-exploitability. No unsupported CPython patch or prerelease is substituted.

**Recommendation: HOLD publication pending a human residual-risk decision and
independent confirmation of GitHub protections.** The High/Critical technical
blockers are resolved; green CI alone is not approval to publish.
A proposed, **not yet approved**, exception is limited to these three advisory
IDs, these exact reviewed simulator inputs and a maximum of 30 days (until
2026-12-10), revoked immediately by a stable fix, new severe finding, external
input, network, HA data, credential or privilege activation. It never covers
future real-mode/deployment applications. No Grype ignore rule implements it.
The justification is the tested absence of network/syscall access and external
inputs, combined with no safe stable package update identified for these three
findings; it is not a general acceptance of vulnerable dependencies.

### Required manual checks before a future publication

1. Independently confirm protected main requires **offline-build** with no
   bypass, and `catalog-publication` requires an explicit reviewer and disables
   administrator bypass. The settings API returned `Forbidden` in this session;
   absence of access is not evidence that settings are correct. The publisher
   now fails closed if `can_admins_bypass` is missing or not strictly false.
2. Review the complete residual-risk table above and final PR checks. Merge only
   through the normal human-reviewed process. No merge or publish is performed
   by this remediation. Re-run validation on the exact resulting main commit.
3. Separately authorize the manual publication workflow with that **40-character
   main SHA** and `PUBLISH-SIMULATION-<same SHA>`, then approve the protected
   environment. No push/PR event can enter the publisher, and its validation
   workflow has only contents:read. Release jobs alone gain package/OIDC rights.
4. Verify the resulting image index/child digests, release-record and GitHub
   attestations against the exact repository, publisher workflow and source SHA.
   Promote store metadata only in another manually reviewed PR after anonymous
   pulls and attestations pass. Do not enable automatic Green updates.

Dependency inputs are pinned, including zlib bytes/signatures and the CI-only
binfmt image. This does not claim bit-for-bit rebuilds across timestamps or
Docker versions. Separately built native-test images have their own IDs;
publication uses the actual saved/tested archives and rechecks payload hashes,
labels, versions, architecture and archive identity. Ordinary image layer deletion
does not erase older base-layer bytes. No secret was put in any such layer.
The healthcheck tests now also wait for Docker's scheduler using root-only 0600
synthetic options and verify the scheduled probe's own unprivileged JSON report.
Root/dirty-env direct probes and six unsafe heartbeat variants remain refused.
