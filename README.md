<!-- markdownlint-disable -->

<p align="center"><h1 align="center">
  URL Sheriff
</h1>

<p align="center">
  validate and prevent against SSRF
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/url-sheriff"><img src="https://badgen.net/npm/v/url-sheriff" alt="npm version"/></a>
  <a href="https://www.npmjs.com/package/url-sheriff"><img src="https://badgen.net/npm/license/url-sheriff" alt="license"/></a>
  <a href="https://www.npmjs.com/package/url-sheriff"><img src="https://badgen.net/npm/dt/url-sheriff" alt="downloads"/></a>
  <a href="https://github.com/lirantal/url-sheriff/actions/workflows/ci.yml"><img src="https://github.com/lirantal/url-sheriff/actions/workflows/ci.yml/badge.svg?branch=main" alt="build"/></a>
  <a href="https://app.codecov.io/gh/lirantal/url-sheriff"><img src="https://badgen.net/codecov/c/github/lirantal/url-sheriff" alt="codecov"/></a>
  <a href="./SECURITY.md"><img src="https://img.shields.io/badge/Security-Responsible%20Disclosure-yellow.svg" alt="Responsible Disclosure Policy" /></a>
</p>

## Install

```sh
npm install --save url-sheriff
```
## Usage

### Basic Usage

```js
import URLSheriff from 'url-sheriff'

const sheriff = new URLSheriff()

await sheriff.isSafeURL('https://example.com') // true

// Throws `URL uses a private hostname`
await sheriff.isSafeURL('http://127.0.0.1:3000')
```

### Secure Defaults

URL Sheriff allows only `http` and `https` URLs by default. A URL being accepted by `new URL()` means it is syntactically valid; it does not mean the URL is safe for a server to access. Hostless URLs and hostnames that resolve to no IP addresses are rejected because URL Sheriff cannot establish a safe network destination.

Scheme checks are applied before hostname, allow-list, and IP-address validation. Configure every additional scheme explicitly and ensure the downstream client is safe for that scheme.

### Using Custom DNS Resolvers

You can specify custom DNS resolvers to use when resolving hostnames:

```js
import URLSheriff from 'url-sheriff'

const sheriff = new URLSheriff({
  dnsResolvers: ['1.1.1.1', '8.8.8.8']
})

// Will use the specified DNS resolvers for hostname lookups
await sheriff.isSafeURL('https://example.com')
```

### Using Allow-lists

URL Sheriff supports allow-lists to specify domains or IP addresses that should be considered safe, even if they would normally be flagged as private or internal.

#### Initializing with an Allow-list

```js
import URLSheriff from 'url-sheriff'

const sheriff = new URLSheriff({
  allowList: [
    'localhost',                    // String literal
    '127.0.0.1',                    // IP address
    /^.*\.internal\.company\.com$/  // RegExp pattern
  ]
})

// This will now return true instead of throwing an error
const isSafe = await sheriff.isSafeURL('http://localhost:3000')
```

#### Managing the Allow-list

You can add or remove entries from the allow-list after initialization:

```js
// Add new entries to the allow-list
sheriff.addToAllowList(['trusted-domain.com', /^api-\d+\.example\.org$/])

// Remove entries from the allow-list
sheriff.removeFromAllowList(['no-longer-trusted.com'])

// Get the current allow-list
const currentAllowList = sheriff.getAllowList()
```

#### How the Allow-list Works

1. When checking if a URL is safe, the hostname is first checked against the allow-list.
2. If the hostname matches any entry in the allow-list (either a string literal or a regex pattern), the URL is immediately considered safe.
3. If the hostname doesn't match any entry in the allow-list, the normal safety checks proceed:
   - Check if the hostname is a valid IP address and if it's private
   - Resolve the hostname to IP addresses and check if any are private

Resolved IP addresses are always checked for private ranges. They are not matched against the allow-list.

### Debug Logging

URLSheriff uses Node.js's built-in `util.debuglog` for debug logging. To enable debug logs, set the `NODE_DEBUG` environment variable to include `url-sheriff`:

```sh
# Enable debug logs for URLSheriff
NODE_DEBUG=url-sheriff node your-app.js

# Enable multiple debug namespaces
NODE_DEBUG=url-sheriff,http,net node your-app.js
```

When debug logging is enabled, URLSheriff will output detailed information about:

- Initialization and configuration
- URL parsing and validation steps
- DNS resolution processes
- Allow-list checks
- IP address validation results

This can be helpful for:
- Troubleshooting URL validation issues
- Understanding why certain URLs are being blocked
- Verifying that DNS resolution is working correctly
- Monitoring allow-list functionality

### Allowed Schemes

The effective default is always `['http', 'https']`:

```js
const sheriff = new URLSheriff()

sheriff.getAllowedSchemes() // ['http', 'https']
```

Opt in to additional schemes explicitly:

```js
const sheriff = new URLSheriff({
  allowedSchemes: ['http', 'https', 'ftp']
})

await sheriff.isSafeURL('ftp://example.com') // true when the host resolves publicly
```

Schemes are matched case-insensitively. Passing an empty list or calling `clearSchemeRestrictions()` restores the secure HTTP/HTTPS defaults:

```js
sheriff.setAllowedSchemes([])
sheriff.getAllowedSchemes() // ['http', 'https']

sheriff.setAllowedSchemes(['ftp'])
sheriff.clearSchemeRestrictions()
sheriff.getAllowedSchemes() // ['http', 'https']
```

Explicitly enabling a scheme does not bypass hostname validation. Hostless URLs such as `file:///etc/passwd` are rejected because there is no network destination to validate. DNS resolution must also return at least one address before a URL can be considered safe.

#### Migrating from 1.x

Version 2.0.0 changes scheme handling to fail closed:

- Unconfigured instances allow HTTP and HTTPS instead of every scheme.
- Consumers that require FTP or another scheme must add it to `allowedSchemes` explicitly.
- `allowedSchemes: []` and `clearSchemeRestrictions()` restore HTTP/HTTPS defaults instead of allowing every scheme.
- `getAllowedSchemes()` returns the effective list instead of `null`.
- Hostless URLs and hostnames resolving to no addresses now throw errors instead of returning `true`.

## References and Prior work

- Python's [safehttpx](https://github.com/gradio-app/safehttpx) library to prevent SSRF

## Contributing

Please consult [CONTRIBUTING](./CONTRIBUTING.md) for guidelines on contributing to this project.

## Author

**url-sheriff** © [Liran Tal](https://github.com/lirantal), Released under the [Apache-2.0](./LICENSE) License.
