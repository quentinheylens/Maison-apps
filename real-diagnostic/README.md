# Real read-only diagnostic 0.8.0

This separate distribution is dormant until its owner locally approves real
reads and the dedicated node's ACL. It does not replace Read Gateway 0.5,
Tailscale or the two simulation applications. Household configuration, data,
credentials and private Git history are never part of this repository.

The source inventory is closed independently from the simulation inventory.
Permissions are checked: Core read adapter, read-only configuration mount,
no Supervisor/Docker/host API, no host ports and no equipment-command route.
Source defaults stay disabled, manual boot, protection on and breaking version.
The application is not advertised in the store before the separate promotion PR.

Publication uses `Publish reviewed real read-only diagnostic`, dispatched on
an exact reviewed public `main` commit with `PUBLISH-REAL-READ-<commit>`.
The existing `catalog-publication` environment must require an owner/reviewer
and forbid administrator bypass. Only the protected publication job has package
write/OIDC/attestation permissions. No installation, production configuration
write, reload or device command is performed by any distribution workflow.

Native ARM64/AMD64 jobs exercise the offline boundary tests, build pinned source,
test without network, check entrypoint/environment/labels and inspect application
bytes inside Docker archives. A fresh Grype scan consumes those exact archives.
High/Critical or any advisory outside the three accepted residual IDs blocks
publication. There are no exemptions and no ignore-unfixed option. The approved
job loads only SHA-256-checked artifacts from its own run, never rebuilds, refuses
existing tags, creates a two-platform index, and records exact digest/commit/run.
GitHub Sigstore provenance is issued for that index and pushed to the registry.
A partial publication is not retried by replacing/deleting tags; use a new version.

Accepted residual advisory IDs, explicitly reviewed for this version:
CVE-2025-60876 (BusyBox, Medium), CVE-2026-116566 (Python, Medium),
CVE-2026-103995 (Python, Low). The compression High GO-2026-6865 is corrected
by rebuilding pinned stable Tailscale with klauspost/compress 1.20.2. The rebuilt
transport carries its own version suffix; it is not represented as an unchanged
upstream binary. Build CA trust is ephemeral and not copied into the runtime.

After successful publication and provenance, download the official
`real-release-record-<run>-<attempt>` artifact and verify its archive SHA-256
against GitHub's artifact metadata. From a clean checkout of its exact public
source commit, run:

```sh
python3 -I -B tools/real_catalog.py promote --root . --release /tmp/release-record.json --output /tmp/real-promotion
```

Promotion requires anonymous GHCR manifest access, matching version/index and
Linux ARM64/AMD64 platforms, verified GitHub provenance for the canonical repo,
source commit, main ref, publish-real workflow, official run/attempt and hosted
runner. It generates only the new application's metadata and its independent
release record. Copy those files into a separate PR; never merge automatically.
Keep the two existing simulations and their release record unchanged. A failed
image pull must not fall back to building source on Green.

See the new application's DOCS.md for the indispensable local installation,
Tailscale ACL, dedicated client credential and Cloud HTTPS connection steps.
No credentials should be entered in a conversation or Git. Real-reader outputs
are private read-only evidence, not deployable configuration or public artifacts.
