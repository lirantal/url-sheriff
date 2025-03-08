<!-- markdownlint-disable -->

<p align="center"><h1 align="center">
  URL Sheriff
</h1>

<p align="center">
  validate and prevent against SSRF
</p>

<p align="center">
  <a href="https://www.npmjs.org/package/url-sheriff"><img src="https://badgen.net/npm/v/url-sheriff" alt="npm version"/></a>
  <a href="https://www.npmjs.org/package/url-sheriff"><img src="https://badgen.net/npm/license/url-sheriff" alt="license"/></a>
  <a href="https://www.npmjs.org/package/url-sheriff"><img src="https://badgen.net/npm/dt/url-sheriff" alt="downloads"/></a>
  <a href="https://github.com/lirantal/url-sheriff/actions?workflow=CI"><img src="https://github.com/lirantal/url-sheriff/workflows/CI/badge.svg" alt="build"/></a>
  <a href="https://codecov.io/gh/lirantal/url-sheriff"><img src="https://badgen.net/codecov/c/github/lirantal/url-sheriff" alt="codecov"/></a>
  <a href="https://snyk.io/test/github/lirantal/url-sheriff"><img src="https://snyk.io/test/github/lirantal/url-sheriff/badge.svg" alt="Known Vulnerabilities"/></a>
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

// initialize
const sheriff = new URLSheriff()

// this will throw an Error exception
sheriff.isSafeURL('http://127.0.0.1:3000')
```

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
4. Additionally, if any of the resolved IP addresses match entries in the allow-list, the URL is considered safe.

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

Initialize with allowed schemes

```js
const sheriff = new URLSheriff({
  allowedSchemes: ['https', 'http']
});
```

Or set allowed schemes after initialization

```js
sheriff.setAllowedSchemes(['https']);
```

Check if a URL is safe

```js
await sheriff.isSafeURL('https://example.com'); // This will pass
await sheriff.isSafeURL('ftp://example.com');   // This will throw an error
```

Get current allowed schemes

```js
const schemes = sheriff.getAllowedSchemes(); // Returns ['https']
```

Remove all scheme restrictions

```js
sheriff.clearSchemeRestrictions();
```

## Contributing

Please consult [CONTRIBUTING](./.github/CONTRIBUTING.md) for guidelines on contributing to this project.

## Author

**url-sheriff** © [Liran Tal](https://github.com/lirantal), Released under the [Apache-2.0](./LICENSE) License.
