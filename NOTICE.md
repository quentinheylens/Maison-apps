# Licences and provenance

The original project code is published for review. No project-wide licence is
granted by this source snapshot; public visibility does not grant an open-source
licence. No personal name or private repository history is needed for this notice.
Any future licensing grant is a separate owner decision.

The only vendored Python dependency is **PyYAML 6.0.3**, under its **MIT** licence.
The full upstream copyright and licence text is preserved as `PyYAML-LICENSE`
inside each application's source folder. The 17 pure-Python modules and licence
were compared byte-for-byte with the official source release. No native PyYAML
extension, libyaml library, credentials or package-manager cache is vendored.
`DEPENDENCIES.json` records the upstream archive URL, SHA-256, licence SHA-256
and every vendored module checksum. Validators work offline against these pins.

Other Python imports belong to the standard library of the pinned Python 3.12
container base. The Dockerfile fixes the public multi-architecture base by SHA-256.
This source review does not distribute an image or claim a complete vulnerability
or licence audit of that base's Alpine/Python packages. Review its package SBOM,
notices and vulnerabilities before a future image publication. No image or
provenance attestation is published by this source snapshot.

SHA-256 pins and source comparisons establish integrity relative to a reviewed
upstream release over HTTPS. They are not a publisher's cryptographic signature.
