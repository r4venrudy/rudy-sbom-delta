# Design and support boundary

Rudy SBOM Delta is an offline comparison and policy-gating CLI. It reads two local JSON files, normalizes supported package/component records, compares them, and optionally returns a nonzero result for selected drift. It does not fetch dependencies or contact registries, vulnerability databases, license services, or build systems.

## Supported document shapes

- SPDX JSON with `spdxVersion` 2.2 or 2.3. Package identity uses the first package URL (`externalRefs[].referenceType == "purl"`) when present, otherwise the case-insensitive package name.
- CycloneDX JSON with `bomFormat == "CycloneDX"` and `specVersion` 1.4, 1.5, 1.6, or 1.7. The metadata root component and nested components are included. A PURL is used when present; generated `bom-ref` values are deliberately ignored because they are often unstable between builds.
- XML, SPDX 3.x, and CycloneDX Protobuf are outside this release's scope.

PURL comparison removes the package version while preserving query qualifiers and fragments. This allows a release change to appear as a version update rather than unrelated add/remove events, while keeping qualifier variants distinct. Without a PURL, name matching can merge same-named packages from separate namespaces; review the identity shown in output and include PURLs in generated SBOMs for better matching.

The tool compares version strings, one selected checksum (SHA-256 when available, otherwise the first recorded checksum), and declared license data. CycloneDX license entries are collected and sorted for stable comparison; this is not a license-expression evaluator. `--deny-license` matches exact identifier tokens, case-insensitively, in candidate license text. It does not determine legal compatibility, interpret exceptions, or replace counsel or a dedicated license-compliance system.

## Input handling

Inputs are limited to 64 MiB each, 1,000,000 parsed JSON values, 128 levels of JSON nesting, and 250,000 normalized components. Duplicate object keys, malformed JSON, unsupported versions, missing component names, and malformed Unicode escapes are rejected. Files are parsed as JSON only. No executable content is evaluated.

## Exit behavior

- `0`: comparison completed and no requested threshold or policy was violated.
- `1`: one or more `--fail-on` categories matched, a denied license was found, or `--require-hashes` found a candidate component without a supported checksum.
- `2`: command-line, file, JSON, or supported-format error.

The exit result is designed for CI. It does not prove that an SBOM is complete, authentic, generated from the build, or representative of a deployed artifact.
