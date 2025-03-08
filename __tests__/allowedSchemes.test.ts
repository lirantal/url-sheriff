import { test, describe, beforeEach, mock } from 'node:test'
import assert from 'node:assert'
import URLSheriff from '../src/main.ts'

describe('URL Scheme Restrictions Tests', () => {
  test('Should handle case-insensitive scheme matching', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowedSchemes: ['HTTP', 'https']
    })
    
    // Act & Assert
    const isSafeHttp = await sheriff.isSafeURL('http://example.com')
    assert.strictEqual(isSafeHttp, true, 'Lower-case HTTP should match upper-case HTTP in the allowed schemes list')
    
    const isSafeHttps = await sheriff.isSafeURL('HTTPS://example.com')
    assert.strictEqual(isSafeHttps, true, 'Upper-case HTTPS should match lower-case HTTPS in the allowed schemes list')
  })

  test('Should allow all URL schemes by default', async () => {
    // Arrange
    const sheriff = new URLSheriff()
    
    // Act & Assert
    const isSafeHttp = await sheriff.isSafeURL('http://example.com')
    assert.strictEqual(isSafeHttp, true, 'HTTP scheme should be allowed by default')
    
    const isSafeHttps = await sheriff.isSafeURL('https://example.com')
    assert.strictEqual(isSafeHttps, true, 'HTTPS scheme should be allowed by default')
    
    const isSafeFtp = await sheriff.isSafeURL('ftp://example.com')
    assert.strictEqual(isSafeFtp, true, 'FTP scheme should be allowed by default')
  })

  test('Should allow URLs with schemes in the allowed schemes list', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowedSchemes: ['http', 'https']
    })
    
    // Act & Assert
    const isSafeHttp = await sheriff.isSafeURL('http://example.com')
    assert.strictEqual(isSafeHttp, true, 'HTTP scheme should be allowed when in allowed schemes list')
    
    const isSafeHttps = await sheriff.isSafeURL('https://example.com')
    assert.strictEqual(isSafeHttps, true, 'HTTPS scheme should be allowed when in allowed schemes list')
  })

  test('Should reject URLs with schemes not in the allowed schemes list', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowedSchemes: ['https']
    })
    
    // Act & Assert
    await assert.rejects(
      sheriff.isSafeURL('http://example.com'),
      {
        name: 'Error',
        message: "URL scheme 'http' is not allowed"
      },
      'HTTP scheme should be rejected when not in allowed schemes list'
    )
    
    await assert.rejects(
      sheriff.isSafeURL('ftp://example.com'),
      {
        name: 'Error',
        message: "URL scheme 'ftp' is not allowed"
      },
      'FTP scheme should be rejected when not in allowed schemes list'
    )
  })

  test('Should allow setting allowed schemes after initialization', async () => {
    // Arrange
    const sheriff = new URLSheriff()
    
    // Initially all schemes should be allowed
    const initialIsSafe = await sheriff.isSafeURL('ftp://example.com')
    assert.strictEqual(initialIsSafe, true, 'All schemes should be allowed initially')
    
    // Act - restrict to HTTPS only
    sheriff.setAllowedSchemes(['https'])
    
    // Assert
    await assert.rejects(
      sheriff.isSafeURL('http://example.com'),
      {
        name: 'Error',
        message: "URL scheme 'http' is not allowed"
      },
      'HTTP scheme should be rejected after restrictions are applied'
    )
    
    const isSafeHttps = await sheriff.isSafeURL('https://example.com')
    assert.strictEqual(isSafeHttps, true, 'HTTPS scheme should still be allowed')
  })

  test('Should get current allowed schemes configuration', () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowedSchemes: ['http', 'https']
    })
    
    // Act
    const allowedSchemes = sheriff.getAllowedSchemes()
    
    // Assert
    assert.deepStrictEqual(allowedSchemes, ['http', 'https'], 'Should return the configured allowed schemes')
  })

  test('Should return null for allowed schemes when all schemes are allowed', () => {
    // Arrange
    const sheriff = new URLSheriff()
    
    // Act
    const allowedSchemes = sheriff.getAllowedSchemes()
    
    // Assert
    assert.strictEqual(allowedSchemes, null, 'Should return null when all schemes are allowed')
  })

  test('Should clear scheme restrictions', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowedSchemes: ['https']
    })
    
    // Verify scheme restriction is working
    await assert.rejects(
      sheriff.isSafeURL('http://example.com'),
      {
        name: 'Error',
        message: "URL scheme 'http' is not allowed"
      },
      'HTTP scheme should be rejected when not in allowed schemes list'
    )
    
    // Act
    sheriff.clearSchemeRestrictions()
    
    // Assert
    const isSafeHttp = await sheriff.isSafeURL('http://example.com')
    assert.strictEqual(isSafeHttp, true, 'HTTP scheme should be allowed after clearing restrictions')
    
    const isSafeFtp = await sheriff.isSafeURL('ftp://example.com')
    assert.strictEqual(isSafeFtp, true, 'FTP scheme should be allowed after clearing restrictions')
  })

  test('Should always check for private IP addresses even with allowed schemes', async (t) => {
    // Arrange
    const sheriff = new URLSheriff({
      allowedSchemes: ['http', 'https']
    })
    
    // Act & Assert
    await assert.rejects(
      sheriff.isSafeURL('http://127.0.0.1'),
      {
        name: 'Error',
        message: 'URL uses a private hostname'
      },
      'Should reject URLs with private IP addresses even if scheme is allowed'
    )
  })

  test('Should verify scheme before checking host or IP addresses', async (t) => {
    // Arrange
    const sheriff = new URLSheriff({
      allowedSchemes: ['https']
    })
    
    // Mock the isPrivateIPAddress method to ensure it would return true
    const isPrivateIPAddressMock = t.mock.method(URLSheriff.prototype, 'isPrivateIPAddress', () => true)
    
    // Act & Assert
    await assert.rejects(
      sheriff.isSafeURL('http://example.com'),
      {
        name: 'Error',
        message: "URL scheme 'http' is not allowed"
      },
      'Should reject URLs with disallowed schemes before checking for private IP addresses'
    )
    
    // Verify the isPrivateIPAddress method was not called since the scheme check failed first
    assert.strictEqual(isPrivateIPAddressMock.mock.callCount(), 0, 'isPrivateIPAddress should not be called for URLs with disallowed schemes')
  })

  test('Should check both scheme and allow list before validating IP addresses', async (t) => {
    // Arrange
    const sheriff = new URLSheriff({
      allowedSchemes: ['https'],
      allowList: ['example.com']
    })
    
    // Mock the isPrivateIPAddress method to see if it gets called
    const isPrivateIPAddressMock = t.mock.method(URLSheriff.prototype, 'isPrivateIPAddress', () => true)
    
    // First, test with disallowed scheme but allowed host
    await assert.rejects(
      sheriff.isSafeURL('http://example.com'),
      {
        name: 'Error',
        message: "URL scheme 'http' is not allowed"
      },
      'Should reject URLs with disallowed schemes even if host is in allow list'
    )
    
    // Verify IP check wasn't called for disallowed scheme
    assert.strictEqual(isPrivateIPAddressMock.mock.callCount(), 0, 'isPrivateIPAddress should not be called for URLs with disallowed schemes')
    
    // Reset mock
    isPrivateIPAddressMock.mock.resetCalls()
    
    // Then, test with allowed scheme and allowed host
    const isSafe = await sheriff.isSafeURL('https://example.com')
    assert.strictEqual(isSafe, true, 'Should allow URLs with allowed schemes and hosts in allow list')
    
    // Verify IP check wasn't called for allowed host
    assert.strictEqual(isPrivateIPAddressMock.mock.callCount(), 0, 'isPrivateIPAddress should not be called for hosts in allow list')
  })

  test('Should handle empty allowed schemes array as allowing all schemes', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowedSchemes: []
    })
    
    // Act & Assert
    const isSafeHttp = await sheriff.isSafeURL('http://example.com')
    assert.strictEqual(isSafeHttp, true, 'HTTP scheme should be allowed with empty allowed schemes array')
    
    const isSafeHttps = await sheriff.isSafeURL('https://example.com')
    assert.strictEqual(isSafeHttps, true, 'HTTPS scheme should be allowed with empty allowed schemes array')
  })
})