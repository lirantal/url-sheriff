import { test, describe, beforeEach, mock } from 'node:test'
import assert from 'node:assert'
import { UrlSheriff } from '../src/main.ts'

describe('SSRF Private Hosts Test Suite', () => {

  beforeEach(() => {
    mock.reset()
  });

  test('If a URL uses a host set to a localhost IP address, an exception is thrown', async (t) => {

    const sheriff = new UrlSheriff({})

    await assert.rejects(
      sheriff.isSafe('http://127.0.0.1:3000'),
      {
        name: 'Error',
        message: 'URL uses a private hostname'
      }
    )

  })

  test('If a URL uses a host set to a localhost domain, an exception is thrown', async (t) => {

    const sheriff = new UrlSheriff({})

    await assert.rejects(
      sheriff.isSafe('http://localhost:3000'),
      {
        name: 'Error',
        message: 'URL uses a private hostname'
      }
    )

  })

  test('If a URL uses a public hostname then it is allowed', async (t) => {
    const sheriff = new UrlSheriff({})
    const isSafe = await sheriff.isSafe('https://example.com')
    assert.strictEqual(isSafe, true);
  })

});