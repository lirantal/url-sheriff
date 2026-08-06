# Secure URL Defaults Design

## Summary

URL Sheriff 1.x allows every URL scheme unless consumers configure `allowedSchemes`. A hostless URL such as `file:///etc/passwd` therefore reaches the system DNS lookup with an empty hostname. Node.js can resolve that lookup to an empty address list, which the current private-address check interprets as safe.

Version 2.0.0 will fail closed at both policy boundaries involved in this behavior: it will allow only HTTP and HTTPS by default, and it will reject URLs for which no hostname or no resolved address can be validated.

## Public behavior

- Constructing `new URLSheriff()` permits only `http` and `https` schemes.
- Passing `allowedSchemes` explicitly permits exactly the listed schemes, normalized case-insensitively.
- Passing `allowedSchemes: []` resets the instance to the secure `http` and `https` defaults.
- Calling `clearSchemeRestrictions()` resets the instance to the secure `http` and `https` defaults. The method name remains unchanged for compatibility, but its documentation will explain the new reset behavior.
- Calling `getAllowedSchemes()` returns the effective scheme list. Under default configuration it returns `['http', 'https']` rather than `null`.
- Consumers that require another network scheme must opt in explicitly, for example `allowedSchemes: ['http', 'https', 'ftp']`.
- A parsed URL with an empty hostname is rejected before allow-list matching or address validation, even when its scheme was explicitly enabled.
- A DNS resolution that produces no addresses is rejected rather than treated as proof that no private address exists.

These changes are intentionally breaking and require a major release.

## Implementation

`src/main.ts` will define one immutable default scheme list containing `http` and `https`. Each instance will receive its own copied array so callers cannot mutate shared defaults through returned values.

Scheme validation will always operate on an effective string array instead of using `null` to represent unrestricted access. `setAllowedSchemes([])` and `clearSchemeRestrictions()` will copy the defaults into instance state. Explicit non-empty lists remain supported and case-insensitive.

`isSafeURL()` will preserve the existing validation order for schemes, then reject an empty normalized hostname before checking the allow-list. This prevents an allow-list expression that matches the empty string from approving hostless URLs.

After either the system or custom DNS path returns, `isSafeURL()` will enforce a shared non-empty-address invariant. The existing custom resolver guard remains useful, while the shared check protects the system resolver and any future resolver implementation.

The errors will remain exceptions, matching the current API:

- Disallowed scheme: `URL scheme '<scheme>' is not allowed`
- Missing hostname: `URL must include a hostname`
- Empty resolution: `Could not resolve hostname: <hostname>`

## Tests

Tests will be written before production changes and observed failing for the expected reasons. Coverage will include:

- HTTP and HTTPS are allowed by default.
- FTP and `file` are rejected by default.
- An explicitly listed additional scheme remains usable when it has a hostname.
- `allowedSchemes: []` restores HTTP/HTTPS defaults.
- `clearSchemeRestrictions()` restores HTTP/HTTPS defaults.
- `getAllowedSchemes()` reports the effective defaults and returns a defensive copy.
- A hostless URL is rejected even when `file` is explicitly listed.
- A mocked system lookup returning an empty address list is rejected.
- Existing private-address, custom-resolver, and allow-list behavior remains covered by the full suite.

## Documentation and release

The README will state that URL parsing only establishes syntactic validity and does not make a URL safe to fetch. It will document the HTTP/HTTPS defaults, explicit opt-in for additional schemes, rejection of hostless URLs, empty-resolution fail-closed behavior, and migration examples for 1.x consumers.

The stale README statement claiming that resolved IP addresses are checked against the allow-list will be removed because that behavior was already removed from the implementation as a security fix.

A Changesets entry will mark `url-sheriff` for a major release and summarize the secure-default migration. The Changesets release workflow will use that entry to produce version 2.0.0; the implementation PR will not manually run the release/version command.

## Scope boundaries

This change does not attempt to solve DNS rebinding inherent in check-then-connect APIs, provide a fetching client or custom agent, or classify the safety semantics of every explicitly enabled non-HTTP scheme. It establishes secure defaults and ensures URL Sheriff never returns `true` when there is no hostname or resolved address to validate.
