import { test, describe, beforeEach, mock } from 'node:test'
import assert from 'node:assert'
import { sheriff } from '../src/main.ts'

describe('SSRF program API', () => {

  beforeEach(() => {
    mock.reset()
  });

  test('If a URL uses a host set to a localhost IP address, an exception is thrown', async (t) => {

    await assert.rejects(
      sheriff('http://localhost:3000'),
      {
        name: 'Error',
        message: 'URL uses a host set to a localhost IP'
      }
    )

  })

});