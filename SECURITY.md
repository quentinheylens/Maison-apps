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
Images carry
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
