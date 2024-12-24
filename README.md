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
## Usage: CLI

```js
import URLSheriff from 'url-sheriff'

// initialize
const sheriff = new URLSheriff()

// this will throw an Error exception
sheriff.isSafeURL('http://127.0.0.1:3000')
```

## Contributing

Please consult [CONTRIBUTING](./.github/CONTRIBUTING.md) for guidelines on contributing to this project.

## Author

**url-sheriff** © [Liran Tal](https://github.com/lirantal), Released under the [Apache-2.0](./LICENSE) License.