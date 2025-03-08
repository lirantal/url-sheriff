import { URL } from 'url'
import { Resolver, lookup } from 'node:dns/promises'
import ipaddress from 'ipaddr.js'
import { LookupAddress } from 'node:dns'
import { debuglog } from 'node:util'

// Initialize debug logger for 'url-sheriff' namespace
const debug = debuglog('url-sheriff')

interface URLSheriffConfig {
  dnsResolvers?: string[]
  allowList?: Array<string | RegExp>
}

export default class URLSheriff {
  #config: URLSheriffConfig
  #resolver?: Resolver
  #allowList: Array<string | RegExp>

  constructor(config: URLSheriffConfig = {}) {
    this.#config = config
    this.#allowList = config.allowList || []

    debug('Initializing URLSheriff with config: %O', this.#config)
    
    if (this.#config.dnsResolvers) {
      debug('Using custom DNS resolvers: %O', this.#config.dnsResolvers)
      this.#resolver = new Resolver()
      this.#resolver.setServers(this.#config.dnsResolvers)
    }
    
    if (this.#allowList.length > 0) {
      debug('Initialized with allow-list entries: %d', this.#allowList.length)
    }
  }

  #getParsedURL(url: string | URL): URL {
    if (typeof url === 'string') {
      try {
        return new URL(url)
      } catch (error) {
        debug('Failed to parse URL string: %s', url)
        throw new Error('Invalid URL provided')
      }
    }

    if (url instanceof URL) {
      debug('Using provided URL object: %s', url.href)
      return url
    }

    debug('Invalid URL type provided: %O', url)
    throw new Error('Invalid URL provided')
  }

  /**
   * Checks if a hostname or IP address matches any entry in the allow-list
   * 
   * @param value The hostname or IP address to check
   * @returns boolean True if the value matches an entry in the allow-list
   */
  #isInAllowList(value: string): boolean {
    return this.#allowList.some(entry => {
      if (typeof entry === 'string') {
        return entry === value
      }
      if (entry instanceof RegExp) {
        return entry.test(value)
      }
      return false
    })
  }

  /**
   * isSafe checks if a URL is safe to use or could result in a potential SSRF
   * 
   * SSRF Validation process:
   * 1. Ensure the string provided is a valid URL structure
   * 2. Check if the hostname is in the allow-list
   * 3. If the URL relies on an IP address, check if it is a private IP address
   * 4. If the URL relies on a hostname, resolve it, and check if it is a private IP address
   * 
   * @param url 
   * @returns boolean
   */
  async isSafeURL(url: string | URL): Promise<boolean> {
    debug('Checking if URL is safe: %s', typeof url === 'string' ? url : url.href)
    
    const parsedUrl = this.#getParsedURL(url)
    const hostname = parsedUrl.hostname
    debug('Extracted hostname: %s', hostname)

    // Check if the hostname is in the allow-list
    if (this.#isInAllowList(hostname)) {
      debug('Hostname is in allow-list, URL is safe: %s', hostname)
      return true
    }

    // as a short-circuit for performance we assume the hostname is an IP address
    // and validate if it is a valid one, then check if it is a private IP address
    if (ipaddress.isValid(hostname)) {      
      if (this.isPrivateIPAddress(hostname)) {
        debug('IP address is private, URL is unsafe: %s', hostname)
        throw new Error('URL uses a private hostname')
      }
      
      debug('IP address is public, URL is safe: %s', hostname)
      return true
    }

    // if it's not a valid ip address as a hostname in the URL, we 
    // perform a DNS lookup to resolve the hostname to an IP address in the most
    // performance efficient way possible and then check if the resolved IP address
    // is a private IP address
    debug('Hostname is not an IP address, resolving via DNS: %s', hostname)

    let ipAddressList: string[] = []
    if (this.#resolver) {
      debug('Using custom DNS resolver')
      ipAddressList = await this.resolveHostnameViaServers(hostname)
    } else {
      debug('Using system DNS resolver')
      ipAddressList = await this.hostnameLookup(hostname)
    }
    
    debug('Resolved hostname %s to IP addresses: %O', hostname, ipAddressList)
    
    // SECURITY FIX: Removed the IP-based allow-list check
    // The following code was removed to prevent SSRF vulnerabilities:
    // const anyIPAddressInAllowList = ipAddressList.some(ipAddress => this.#isInAllowList(ipAddress))
    // if (anyIPAddressInAllowList) {
    //   return true
    // }
    
    const anyIPAddressIsPrivate: boolean = ipAddressList.some(ipAddress => {
      const isPrivate = this.isPrivateIPAddress(ipAddress)
      if (isPrivate) {
        debug('Found private IP address in resolution: %s', ipAddress)
      }
      return isPrivate
    })

    if (anyIPAddressIsPrivate) {
      debug('URL resolves to private IP address, URL is unsafe: %s', hostname)
      throw new Error('URL uses a private hostname')
    }

    debug('All IP addresses are public, URL is safe: %s', hostname)
    return true;
  }

  isPrivateIPAddress(ipAddress: string): boolean {    
    let ip = ipaddress.parse(ipAddress)

    if (ip instanceof ipaddress.IPv6 && ip.isIPv4MappedAddress()) {
      ip = ip.toIPv4Address()
    }

    const range = ip.range()    
    if (range !== 'unicast') {
      debug('IP address is private (non-unicast range): %s', ipAddress)
      return true
    }

    debug('IP address is public: %s', ipAddress)
    return false
  }

  /**
   * 
   * @param hostname the hostname to perform a DNS lookup for
   * @returns string[] the list of resolved IP addresses
   */
  async hostnameLookup(hostname: string): Promise<string[]> {    
    try {
      const ipAddressListDetails: LookupAddress[] = await lookup(hostname, { all: true })
      const ipAddressList = ipAddressListDetails.map(ipAddressDetails => {
        return ipAddressDetails.address
      })
      
      return ipAddressList
    } catch (error) {
      debug('Error looking up hostname %s: %O', hostname, error)
      throw error
    }
  }

  /**
   * 
   * @param hostname the hostname to perform a DNS lookup for
   * @returns string[] the list of resolved IP addresses
   */
  async resolveHostnameViaServers(hostname: string): Promise<string[]> {    
    if (!this.#resolver) {
      throw new Error('DNS resolver is not defined');
    }
    
    try {
      const ipAddressList: string[] = await this.#resolver.resolve4(hostname)
      return ipAddressList
    } catch (error) {
      debug('Error resolving hostname %s with custom resolvers: %O', hostname, error)
      throw error
    }
  }

  /**
   * Add entries to the allow-list
   * 
   * @param entries Array of string literals or RegExp patterns to add to the allow-list
   */
  addToAllowList(entries: Array<string | RegExp>): void {
    debug('Adding %d entries to allow-list', entries.length)
    this.#allowList = [...this.#allowList, ...entries]
  }

  /**
   * Remove entries from the allow-list
   * 
   * @param entries Array of string literals or RegExp patterns to remove from the allow-list
   */
  removeFromAllowList(entries: Array<string | RegExp>): void {
    this.#allowList = this.#allowList.filter(existing => {
      return !entries.some(entry => {
        if (typeof entry === 'string' && typeof existing === 'string') {
          return entry === existing
        }
        if (entry instanceof RegExp && existing instanceof RegExp) {
          return entry.toString() === existing.toString()
        }
        return false
      })
    })
  }

  /**
   * Get the current allow-list
   * 
   * @returns Array<string | RegExp> The current allow-list
   */
  getAllowList(): Array<string | RegExp> {
    return [...this.#allowList]
  }
}
