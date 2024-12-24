import { test, describe, beforeEach, mock } from 'node:test'
import assert from 'node:assert'
import URLSheriff from '../src/main.ts'

describe('SSRF Private Hosts Test Suite', () => {

  beforeEach(() => {
    mock.reset()
  });

  test('If a URL uses a host set to a localhost IP address, an exception is thrown', async (t) => {

    const sheriff = new URLSheriff()

    await assert.rejects(
      sheriff.isSafeURL('http://127.0.0.1:3000'),
      {
        name: 'Error',
        message: 'URL uses a private hostname'
      }
    )

  })

  test('If a URL uses a host set to a localhost domain, an exception is thrown', async (t) => {

    const sheriff = new URLSheriff({})

    await assert.rejects(
      sheriff.isSafeURL('http://localhost:3000'),
      {
        name: 'Error',
        message: 'URL uses a private hostname'
      }
    )

  })

  test('If a URL uses a public hostname then it is allowed', async (t) => {
    const sheriff = new URLSheriff({})
    const isSafe = await sheriff.isSafeURL('https://example.com')
    assert.strictEqual(isSafe, true);
  })

  test('If a URL uses a public IP address in the range of 172.32.0.0 then it should be allowed', async (t) => {
    const sheriff = new URLSheriff({})
    const isSafe = await sheriff.isSafeURL('https://172.32.1.2')
    assert.strictEqual(isSafe, true);
  })

});