import { test, describe, beforeEach, mock } from 'node:test'
import assert from 'node:assert'
import URLSheriff from '../src/main.ts'
import { Resolver } from 'node:dns/promises'

function createDnsError(code: string): NodeJS.ErrnoException {
  const error = new Error(`DNS lookup failed with ${code}`) as NodeJS.ErrnoException
  error.code = code
  return error
}

describe('DNS Resolver Tests', () => {
  beforeEach(() => {
    mock.reset()
  });

  test('Providing custom DNS resolver servers uses the custom resolver for DNS lookups', async (t) => {
    const customResolvers = ['1.1.1.1', '8.8.8.8']

    // Mock the Resolver class and its DNS methods
    const resolverMock = t.mock.method(Resolver.prototype, 'setServers')
    const resolve4Mock = t.mock.method(Resolver.prototype, 'resolve4', async () => ['93.184.216.34'])
    const resolve6Mock = t.mock.method(Resolver.prototype, 'resolve6', async () => {
      throw createDnsError('ENODATA')
    })

    const sheriff = new URLSheriff({
      dnsResolvers: customResolvers
    })

    const isSafe = await sheriff.isSafeURL('https://example.com')
    assert.strictEqual(isSafe, true)

    // Verify that Resolver.prototype.setServers was called with the custom resolvers
    assert.strictEqual(resolverMock.mock.callCount(), 1, 'setServers should be called once')
    assert.deepStrictEqual(resolverMock.mock.calls[0].arguments[0], customResolvers, 'setServers should be called with custom resolvers')
    assert.strictEqual(resolve4Mock.mock.callCount(), 1, 'resolve4 should be called once')
    assert.strictEqual(resolve6Mock.mock.callCount(), 1, 'resolve6 should be called once')
  })

  test('When no custom DNS resolvers are provided, the default lookup should be used', async (t) => {
    // Mock the Resolver class and its setServers method
    const resolverMock = t.mock.method(Resolver.prototype, 'setServers')

    const sheriff = new URLSheriff()
    await sheriff.isSafeURL('https://example.com')

    // Verify setServers was NOT called since we didn't provide custom resolvers
    assert.strictEqual(resolverMock.mock.callCount(), 0, 'setServers should not be called')
  })

  test('Should throw error when DNS resolver is not defined but resolveHostnameViaServers is called directly', async (t) => {
    const sheriff = new URLSheriff()
    
    await assert.rejects(
      () => sheriff.resolveHostnameViaServers('example.com'),
      {
        name: 'Error',
        message: 'DNS resolver is not defined'
      }
    )
  })

  test('Custom DNS resolvers should return IPv4 and IPv6 addresses', async (t) => {
    const resolve4Mock = t.mock.method(Resolver.prototype, 'resolve4', async () => ['93.184.216.34'])
    const resolve6Mock = t.mock.method(Resolver.prototype, 'resolve6', async () => ['2606:2800:220:1:248:1893:25c8:1946'])

    const sheriff = new URLSheriff({
      dnsResolvers: ['1.1.1.1']
    })

    const addresses = await sheriff.resolveHostnameViaServers('example.com')

    assert.deepStrictEqual(addresses, ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'])
    assert.strictEqual(resolve4Mock.mock.callCount(), 1, 'resolve4 should be called once')
    assert.strictEqual(resolve6Mock.mock.callCount(), 1, 'resolve6 should be called once')
  })

  test('Custom DNS resolvers should reject IPv6-only private hostnames as private', async (t) => {
    t.mock.method(Resolver.prototype, 'resolve4', async () => {
      throw createDnsError('ENODATA')
    })
    const resolve6Mock = t.mock.method(Resolver.prototype, 'resolve6', async () => ['::1'])

    const sheriff = new URLSheriff({
      dnsResolvers: ['1.1.1.1']
    })

    await assert.rejects(
      sheriff.isSafeURL('https://ipv6-private.example'),
      {
        name: 'Error',
        message: 'URL uses a private hostname'
      }
    )
    assert.strictEqual(resolve6Mock.mock.callCount(), 1, 'resolve6 should be called once')
  })

  test('Custom DNS resolvers should allow public IPv6-only hostnames', async (t) => {
    t.mock.method(Resolver.prototype, 'resolve4', async () => {
      throw createDnsError('ENODATA')
    })
    t.mock.method(Resolver.prototype, 'resolve6', async () => ['2606:2800:220:1:248:1893:25c8:1946'])

    const sheriff = new URLSheriff({
      dnsResolvers: ['1.1.1.1']
    })

    const isSafe = await sheriff.isSafeURL('https://ipv6-public.example')
    assert.strictEqual(isSafe, true)
  })

  test('Should handle invalid DNS resolver addresses appropriately', async (t) => {
    // Arrange
    const invalidIpAddress = '999.999.999.999'
    
    // Act & Assert
    assert.throws(
      () => {
        new URLSheriff({
          dnsResolvers: [invalidIpAddress]
        })
      },
      {
        name: 'TypeError',
        code: 'ERR_INVALID_IP_ADDRESS'
      },
      'Should throw a TypeError when an invalid IP address is provided as DNS resolver'
    )
    
    // Test with non-IP string
    assert.throws(
      () => {
        new URLSheriff({
          dnsResolvers: ['not-an-ip-address']
        })
      },
      {
        name: 'TypeError',
        code: 'ERR_INVALID_IP_ADDRESS'
      },
      'Should throw a TypeError when a non-IP string is provided as DNS resolver'
    )
  })
})
