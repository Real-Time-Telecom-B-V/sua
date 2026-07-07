# Versioning

`sua` follows [Semantic Versioning 2.0.0](https://semver.org/). The public
API, the `SuaMessage` codec, the `CommonHeader` / `MessageClass` /
`MessageType` types, `Parameter` and the `tags` constants, the `SuaAddress` /
`GlobalTitle` / `RoutingIndicator` address types, and `SuaError`, is the
contract.

## The git tag is the source of truth

`Cargo.toml`'s `version` matches the release tag; the release workflow's
`verify-version` job refuses to publish if they disagree. Bump `version`, commit,
tag `vX.Y.Z`, push the tag.

## Post-1.0 rule

- **MAJOR**, remove / rename / re-signature a `pub` item, or change documented
  wire semantics.
- **MINOR**, backward-compatible additions (new message builders, new
  `MessageType` / parameter `tags`, new accessors).
- **PATCH**, bug fixes, docs, behaviour-neutral dependency bumps.
