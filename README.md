# Maison — Simulation applications

This repository separates source review, approved image publication and store
promotion. Definitions under `sources/` are not installable store entries.
Repository: `quentinheylens/Maison-apps`. Enabling `publication_enabled` does not
publish an image: publication still requires a manual workflow, the exact main
commit and explicit GitHub environment approval. Store promotion requires a
separate reviewed pull request.

Only generic code, synthetic fixtures and pinned pure-Python YAML support belong
here. No private configuration repository, history, installation identifiers,
tokens or household data is distributed. No licence to the project's original
code is granted by public visibility alone; obtain the owner's licensing decision
before granting a project-wide licence. The bundled PyYAML licence remains included.
See [NOTICE.md](NOTICE.md) and [DEPENDENCIES.json](DEPENDENCIES.json) for the
vendored dependency's upstream source, licence and file checksums. GitHub's
repository spelling is preserved; only GHCR image/package paths are lowercased.

## iPhone: add once, then install manually

After the owner approves publication and the two images and catalogue entries
are available:

1. In Home Assistant, open **Settings → Apps / Add-ons → App store → ⋮ → Repositories**.
2. Add `https://github.com/quentinheylens/Maison-apps` and confirm.
3. Select **Maison Diagnostic Gateway 0.6 (simulation)** or **Maison Deployment
   Simulator**, check the version, then tap **Install**. Starting is a separate choice.

Keep protection on. Disable auto-update, autostart and watchdog. Options must stay
`mode: simulation`, `network_enabled: false`, `execution_enabled: false`. The
applications do not use HA/Supervisor, listen, join Tailscale or write production.
Existing Read Gateway and Tailscale applications are independent and untouched.
Future approved versions appear with a manual **Update** button. Every version
is marked as breaking to prevent automatic upgrades. Updating a running simulator
may stop/start that simulator: perform it only after review.

## Maintainer: development → tested → approved

- `sources/` is never an installable app folder. CI validates the closed source
  inventory, builds ARM64/AMD64 and exercises AMD64 simulations without networking.
- `catalog-policy.json` starts with `publication_enabled: false`. Enable it only
  in a reviewed commit after explicit publication consent. Configure a pre-existing
  `catalog-publication` environment with a required owner/reviewer and disable
  administrator bypass. Protect `main`, require review and CI; forbid force pushes.
- Dispatch **Publish reviewed simulation images** on `main`, with its exact commit
  and `PUBLISH-SIMULATION-<commit>`. Read-only builds precede the environment approval.
  Only the approved job may write packages or request OIDC provenance. It never
  receives credentials for any other repository or Home Assistant.
- GHCR may create packages private by default. After explicit approval, make only
  the two new simulation packages public via GitHub's package settings. No token
  needs to be installed on the Green. Do not change visibility of other packages.
- Download the release record from that successful run. In a clean checkout of
  its exact public commit, a maintainer with recent `gh` and Docker runs:

  ```sh
  python3 -I tools/catalog.py promote --root . --release /tmp/release-record.json --output /tmp/catalog-promotion
  ```

  This requires anonymous registry access, matching tag digests and GitHub
  attestations for this workflow and source commit. It prepares metadata only.
  Review the small promotion files in a **separate PR**. Only its manually approved
  merge advertises the version to the store. Never copy all build output into Git.
- New versions originate in the private development process, undergo a new
  exhaustive export review and repeat these stages. Preserve already approved
  app metadata until promotion. Do not replace an old version's source by merging
  an entire fresh proposal blindly.

The store loads app configs only at repository root subdirectories, once a
promotion adds them. No source-build fallback Dockerfile is provided there. If
an approved registry image is unavailable, installation fails instead of building
unreviewed code on Green. Source code and the pinned base remain reproducible inputs,
not a claim that image bytes rebuild identically.

## Recovery and rollback

Never reuse a published version tag. A failure after a partial push leaves orphan
images, not a new store entry; do not retry by deleting/replacing tags. Keep the
tested artifacts and any release record for audit, then prepare a new version.
If attestation fails, do not promote; review and rerun the attestation on the same
digest through an explicitly reviewed maintenance operation, or use a new version.
First-publication visibility changes do not require a repush: change only those
package settings, then run `promote` against the original record.

Stop/uninstall only the new simulator to disable it; no production restore is
needed. For a failed simulator update, restore its HA backup manually if present,
or publish a **new increasing version** from previously reviewed code through the
same chain. Moving the catalogue to a lower version does not force a downgrade.
Preserve old version tags/digests and release records; no garbage collection is automated.

Read [SECURITY.md](SECURITY.md) before enabling distribution.

## Security remediation review

See [the complete security report](SECURITY.md#result-and-residual-risk-decision)
for the 152-row baseline triage, pinned runtime changes, native tests, remaining
advisories and publication hold. The two applications remain sealed simulations;
no image or store promotion is performed by this PR.
