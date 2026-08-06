# Secure URL Defaults Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make URL Sheriff fail closed for schemes, hostnames, and DNS results that cannot be safely validated, and prepare the breaking behavior for a 2.0.0 release.

**Architecture:** Store an effective scheme allow-list on every `URLSheriff` instance, initialized from immutable HTTP/HTTPS defaults. Validate scheme and hostname before allow-list/IP handling, then enforce a non-empty result after either DNS resolution path so every affirmative result has passed a concrete safety check.

**Tech Stack:** TypeScript, Node.js 24 test runner, `ts-node`, Changesets, npm

## Global Constraints

- The default and reset scheme list is exactly `['http', 'https']`.
- Explicit non-empty `allowedSchemes` values remain supported and case-insensitive.
- Empty hostnames are rejected before allow-list matching.
- Empty DNS results are rejected after either resolver path.
- No new runtime dependency is introduced.
- The change is recorded as a major Changesets release; package versions are not manually published from this branch.
- Preserve the pre-existing unstaged `package-lock.json` change and do not include it unless a task explicitly requires it.

---

### Task 1: Secure scheme defaults

**Files:**
- Modify: `__tests__/allowedSchemes.test.ts`
- Modify: `src/main.ts`

**Interfaces:**
- Consumes: `URLSheriffConfig.allowedSchemes?: string[]`
- Produces: `setAllowedSchemes(schemes: string[]): string[]`, `getAllowedSchemes(): string[]`, and `clearSchemeRestrictions(): void` with effective HTTP/HTTPS defaults

- [ ] **Step 1: Replace permissive-default tests with secure-default expectations**

Update `__tests__/allowedSchemes.test.ts` so default construction allows HTTP and HTTPS but rejects FTP:

```ts
test('Should allow only HTTP and HTTPS schemes by default', async () => {
  const sheriff = new URLSheriff()

  assert.strictEqual(await sheriff.isSafeURL('http://example.com'), true)
  assert.strictEqual(await sheriff.isSafeURL('https://example.com'), true)
  await assert.rejects(sheriff.isSafeURL('ftp://example.com'), {
    name: 'Error',
    message: "URL scheme 'ftp' is not allowed"
  })
})
```

Change the getter test to expect `['http', 'https']`. Change the empty-array and clear tests to verify they restore those defaults and reject FTP. Add an explicit opt-in test:

```ts
test('Should allow explicitly configured additional schemes', async () => {
  const sheriff = new URLSheriff({ allowedSchemes: ['HTTPS', 'ftp'] })

  assert.deepStrictEqual(sheriff.getAllowedSchemes(), ['https', 'ftp'])
  assert.strictEqual(await sheriff.isSafeURL('ftp://example.com'), true)
})
```

Add a defensive-copy assertion by mutating the array returned from `getAllowedSchemes()` and confirming a later call still returns `['http', 'https']`.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `node --loader ts-node/esm --test __tests__/allowedSchemes.test.ts`

Expected: FAIL because default FTP is currently allowed, default getter returns `null`, and reset operations currently remove all restrictions.

- [ ] **Step 3: Implement effective secure defaults**

In `src/main.ts`, add the module constant and make instance state non-nullable:

```ts
const DEFAULT_ALLOWED_SCHEMES = ['http', 'https'] as const

#allowedSchemes: string[]
```

Initialize with a copied default when configuration is omitted:

```ts
this.#allowedSchemes = typeof config.allowedSchemes === 'undefined'
  ? [...DEFAULT_ALLOWED_SCHEMES]
  : this.setAllowedSchemes(config.allowedSchemes)
```

Make the scheme check unconditional and make empty/reset operations copy the defaults:

```ts
#isSchemeAllowed(scheme: string): boolean {
  return this.#allowedSchemes.includes(scheme.toLowerCase())
}

setAllowedSchemes(schemes: string[]): string[] {
  this.#allowedSchemes = schemes.length === 0
    ? [...DEFAULT_ALLOWED_SCHEMES]
    : schemes.map(scheme => scheme.toLowerCase())
  return [...this.#allowedSchemes]
}

getAllowedSchemes(): string[] {
  return [...this.#allowedSchemes]
}

clearSchemeRestrictions(): void {
  this.#allowedSchemes = [...DEFAULT_ALLOWED_SCHEMES]
}
```

Update adjacent comments and debug conditions so they describe effective allowed schemes rather than unrestricted/null state.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `node --loader ts-node/esm --test __tests__/allowedSchemes.test.ts`

Expected: all allowed-scheme tests pass.

- [ ] **Step 5: Commit the scheme-default change**

Stage only `src/main.ts` and `__tests__/allowedSchemes.test.ts`.

Commit: `fix: default to secure URL schemes`

---

### Task 2: Fail closed for missing hosts and addresses

**Files:**
- Modify: `__tests__/isSafeURL.sanity.test.ts`
- Modify: `src/main.ts`

**Interfaces:**
- Consumes: normalized `URL.hostname`, `hostnameLookup(hostname): Promise<string[]>`, and `resolveHostnameViaServers(hostname): Promise<string[]>`
- Produces: rejection with `URL must include a hostname` or `Could not resolve hostname: <hostname>` when validation evidence is absent

- [ ] **Step 1: Add failing host and address regression tests**

Add these behaviors to `__tests__/isSafeURL.sanity.test.ts`:

```ts
test('If an explicitly allowed scheme has no hostname, an exception is thrown before lookup', async (t) => {
  const sheriff = new URLSheriff({ allowedSchemes: ['file'] })
  const hostnameLookupMock = t.mock.method(sheriff, 'hostnameLookup', async () => {
    assert.fail('Hostless URLs must be rejected before DNS lookup')
  })

  await assert.rejects(sheriff.isSafeURL('file:///etc/passwd'), {
    name: 'Error',
    message: 'URL must include a hostname'
  })
  assert.strictEqual(hostnameLookupMock.mock.callCount(), 0)
})

test('If hostname resolution returns no addresses, an exception is thrown', async (t) => {
  const sheriff = new URLSheriff()
  t.mock.method(sheriff, 'hostnameLookup', async () => [])

  await assert.rejects(sheriff.isSafeURL('https://example.com'), {
    name: 'Error',
    message: 'Could not resolve hostname: example.com'
  })
})
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `node --loader ts-node/esm --test __tests__/isSafeURL.sanity.test.ts`

Expected: the hostless test returns `true`, and the empty-resolution test returns `true`.

- [ ] **Step 3: Implement fail-closed invariants**

After scheme validation and before allow-list validation in `isSafeURL()`:

```ts
if (hostname.length === 0) {
  debug('URL does not include a hostname')
  throw new Error('URL must include a hostname')
}
```

After the resolver branch and before private-address iteration:

```ts
if (ipAddressList.length === 0) {
  debug('Hostname did not resolve to any IP addresses: %s', hostname)
  throw new Error(`Could not resolve hostname: ${hostname}`)
}
```

- [ ] **Step 4: Run focused and related resolver tests and verify GREEN**

Run: `node --loader ts-node/esm --test __tests__/isSafeURL.sanity.test.ts __tests__/customResolver.test.ts`

Expected: all sanity and custom-resolver tests pass.

- [ ] **Step 5: Commit the fail-closed validation change**

Stage only `src/main.ts` and `__tests__/isSafeURL.sanity.test.ts`.

Commit: `fix: reject URLs without verifiable hosts`

---

### Task 3: Document the breaking security behavior

**Files:**
- Modify: `README.md`
- Create: `.changeset/secure-url-defaults.md`

**Interfaces:**
- Consumes: the final public behavior from Tasks 1 and 2
- Produces: consumer migration guidance and a major-release Changesets entry

- [ ] **Step 1: Rewrite README usage around the secure default**

Update Basic Usage to await the call and show both a public HTTPS URL and rejected private URL. Add a security-default explanation stating:

```md
URL Sheriff allows only `http` and `https` URLs by default. A URL being accepted by `new URL()` means it is syntactically valid; it does not mean the URL is safe for a server to access. Hostless URLs and hostnames that resolve to no IP addresses are rejected because URL Sheriff cannot establish a safe network destination.
```

Replace the stale resolved-IP allow-list step with documentation matching the current hostname-only short circuit.

Rewrite Allowed Schemes to show explicit opt-in:

```js
const sheriff = new URLSheriff({
  allowedSchemes: ['http', 'https', 'ftp']
})
```

Document that `allowedSchemes: []` and `clearSchemeRestrictions()` restore HTTP/HTTPS defaults. Add a 1.x migration note explaining that consumers needing other schemes must list them explicitly and that hostless schemes are no longer accepted.

- [ ] **Step 2: Add the major Changesets entry**

Create `.changeset/secure-url-defaults.md`:

```md
---
"url-sheriff": major
---

Default URL validation to HTTP and HTTPS, reject hostless URLs and empty DNS results, and make empty or cleared scheme configuration restore the secure defaults.
```

- [ ] **Step 3: Review documentation against implemented behavior**

Run: `rg -n -C 3 "allow-list|Allowed Schemes|allowedSchemes|hostless|resolve" README.md`

Expected: no claim remains that resolved IPs are allow-listed; defaults and migration behavior match the tests.

- [ ] **Step 4: Commit documentation and release metadata**

Stage only `README.md` and `.changeset/secure-url-defaults.md`.

Commit: `docs: explain secure URL validation defaults`

---

### Task 4: Verify and publish the branch

**Files:**
- Verify: all committed files in this plan
- Preserve unstaged: `package-lock.json`

**Interfaces:**
- Consumes: completed implementation and documentation commits
- Produces: a pushed branch and draft GitHub pull request targeting the default branch

- [ ] **Step 1: Run all project checks from a fresh state**

Run each command and require exit code 0:

```sh
npm test
npm run lint
npm run build
```

- [ ] **Step 2: Inspect final scope and history**

Run:

```sh
git status -sb
git diff origin/main...HEAD --stat
git log --oneline origin/main..HEAD
```

Expected: only the design, plan, tests, implementation, README, and Changesets entry are committed; the pre-existing `package-lock.json` change remains unstaged.

- [ ] **Step 3: Verify GitHub CLI authentication**

Run: `gh --version`

Run: `gh auth status`

Expected: GitHub CLI is installed and authenticated for `github.com`.

- [ ] **Step 4: Push the feature branch**

Run: `git push -u origin work/secure-url-defaults`

Expected: the branch tracks `origin/work/secure-url-defaults`.

- [ ] **Step 5: Open a draft pull request**

Create a draft PR targeting `main` with title `fix: enforce secure URL defaults`. The body must summarize the vulnerability root cause, new HTTP/HTTPS default, explicit migration path, breaking-change/major-release impact, and exact verification commands.

- [ ] **Step 6: Report publication details**

Provide the branch, commit list, PR URL, checks, and note that `package-lock.json` remains a pre-existing unstaged change outside the PR.
