import { test, describe } from 'node:test'
import assert from 'node:assert'
import URLSheriff from '../src/main.ts'


describe('Allow-list Tests', () => {
  test('Should allow URLs with hostnames in the allow-list', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowList: ['localhost', 'internal.example.com']
    })

    // Act & Assert
    const isSafe = await sheriff.isSafeURL('https://localhost/api')
    assert.strictEqual(isSafe, true, 'URL with hostname in allow-list should be considered safe')
  })

  test('Should allow URLs with ip addresses in the allow-list', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowList: ['1.1.1.1']
    })

    // Act & Assert
    const isSafe = await sheriff.isSafeURL('https://1.1.1.1/api')
    assert.strictEqual(isSafe, true, 'URL with IP addresses in allow-list should be considered safe')
  })

  test('Should allow URLs with hostnames matching regex patterns in the allow-list', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowList: [/^.*\.internal\.example\.com$/, /^dev-\d+\.test\.com$/]
    })

    // Act & Assert
    const isSafe1 = await sheriff.isSafeURL('https://api.internal.example.com/endpoint')
    assert.strictEqual(isSafe1, true, 'URL matching first regex pattern should be considered safe')

    const isSafe2 = await sheriff.isSafeURL('https://dev-123.test.com/api')
    assert.strictEqual(isSafe2, true, 'URL matching second regex pattern should be considered safe')
  })

  test('Should allow adding entries to the allow-list after initialization', async () => {
    // Arrange
    const sheriff = new URLSheriff()
    
    // Act
    sheriff.addToAllowList(['dynamic-allow.example.com', /^dynamic-\d+\.example\.com$/])
    
    // Assert
    const isSafe1 = await sheriff.isSafeURL('https://dynamic-allow.example.com/api')
    assert.strictEqual(isSafe1, true, 'URL with hostname added to allow-list should be considered safe')
    
    const isSafe2 = await sheriff.isSafeURL('https://dynamic-123.example.com/api')
    assert.strictEqual(isSafe2, true, 'URL matching regex pattern added to allow-list should be considered safe')
  })

  test('Should allow removing entries from the allow-list', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowList: ['temp.example.com', /^temp-\d+\.example\.com$/]
    })
    
    // Verify entries are initially allowed
    const initialIsSafe = await sheriff.isSafeURL('https://temp.example.com/api')
    assert.strictEqual(initialIsSafe, true, 'URL should initially be in allow-list')
    
    // Act
    sheriff.removeFromAllowList(['temp.example.com'])
    
    // Assert - this should now throw an error if the hostname resolves to a private IP
    // Since we can't guarantee the resolution in a test, we'll check that the entry was removed
    const allowList = sheriff.getAllowList()
    assert.strictEqual(allowList.length, 1, 'One entry should remain in the allow-list')
    assert.strictEqual(allowList[0] instanceof RegExp, true, 'Remaining entry should be the RegExp')
  })

  test('Should prioritize allow-list over private IP checks', async (t) => {
    // Arrange
    const sheriff = new URLSheriff({
      allowList: ['localhost', '127.0.0.1', '::1']
    })
    
    // Mock the isPrivateIPAddress method to ensure it would normally return true
    const isPrivateIPAddressMock = t.mock.method(URLSheriff.prototype, 'isPrivateIPAddress', () => true)
    
    // Act & Assert
    const isSafe = await sheriff.isSafeURL('https://localhost/api')
    assert.strictEqual(isSafe, true, 'URL with hostname in allow-list should be considered safe even if it would resolve to a private IP')
    
    // Verify the isPrivateIPAddress method was not called since the hostname was in the allow-list
    assert.strictEqual(isPrivateIPAddressMock.mock.callCount(), 0, 'isPrivateIPAddress should not be called for hostnames in the allow-list')
  })

  test('Should not allow URLs with resolved IPs in allow-list if hostname is not allowed', async () => {
    // Arrange
    const sheriff = new URLSheriff({
      allowList: ['127.0.0.1', 'localhost']
    })
    
    // Mock the DNS resolution to simulate a malicious domain resolving to an allowed IP
    const originalHostnameLookup = sheriff.hostnameLookup
    sheriff.hostnameLookup = async () => {
      return ['127.0.0.1', '8.8.8.8'] // Simulate evil.com resolving to 127.0.0.1
    }
    
    try {
      // Act
      await sheriff.isSafeURL('https://evil.com')
      
      // If we get here, the test failed because the URL was incorrectly allowed
      assert.fail('URL with resolved IP in allow-list should not be allowed if hostname is not in allow-list')
    } catch (error) {
      // Assert
      assert.strictEqual(
        (error as Error).message, 
        'URL uses a private hostname', 
        'Should throw the correct error message'
      )
    } finally {
      // Restore the original method
      sheriff.hostnameLookup = originalHostnameLookup
    }
  })
})