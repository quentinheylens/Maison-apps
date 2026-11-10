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
