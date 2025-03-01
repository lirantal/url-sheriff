import { URL } from 'url'
import { Resolver, lookup } from 'node:dns/promises'
import ipaddress from 'ipaddr.js'
import { LookupAddress } from 'node:dns'

interface URLSheriffConfig {
  dnsResolvers?: string[]
}

export default class URLSheriff {
  #config: URLSheriffConfig
  #resolver?: Resolver

  constructor(config: URLSheriffConfig = {}) {
    this.#config = config

    if (this.#config.dnsResolvers) {
      this.#resolver = new Resolver()
      this.#resolver.setServers(this.#config.dnsResolvers)
    }
  }

  #getParsedURL(url: string | URL): URL {
    if (typeof url === 'string') {
      try {
        return new URL(url)
      } catch (error) {
        throw new Error('Invalid URL provided')
      }
    }

    if (url instanceof URL) {
      return url
    }

    throw new Error('Invalid URL provided')
  }

  /**
   * isSafe checks if a URL is safe to use or could result in a potential SSRF
   * 
   * SSRF Validation process:
   * 1. Ensure the string provided is a valid URL structure
   * 2. If the URL relies on an IP address, check if it is a private IP address
   * 3. If the URL relies on a hostname, resolve it, and check if it is a private IP address
   * 
   * @param url 
   * @returns boolean
   */
  async isSafeURL(url: string | URL): Promise<boolean> {

    const parsedUrl = this.#getParsedURL(url)
    const hostname = parsedUrl.hostname

    // as a short-circuit for performance we assume the hostname is an IP address
    // and validate if it is a valid one, then check if it is a private IP address
    if (ipaddress.isValid(hostname)) {
      if (this.isPrivateIPAddress(hostname)) {
        throw new Error('URL uses a private hostname')
      }
      return true
    }

    // if it's not a valid ip address as a hostname in the URL, we 
    // perform a DNS lookup to resolve the hostname to an IP address in the most
    // performance efficient way possible and then check if the resolved IP address
    // is a private IP address

    let ipAddressList: string[] = []
    if (this.#resolver) {
      ipAddressList = await this.resolveHostnameViaServers(hostname)
    } else {
      ipAddressList = await this.hostnameLookup(hostname)
    }
    
    const anyIPAddressIsPrivate: boolean = ipAddressList.some(ipAddress => {
      return this.isPrivateIPAddress(ipAddress)
    })

    if (anyIPAddressIsPrivate) {
      throw new Error('URL uses a private hostname')
    }

    return true;
  }

  isPrivateIPAddress(ipAddress: string): boolean {
    let ip = ipaddress.parse(ipAddress)

    if (ip instanceof ipaddress.IPv6 && ip.isIPv4MappedAddress()) {
      ip = ip.toIPv4Address()
    }

    if (ip.range() !== 'unicast') {
      return true
    }

    return false
  }

  /**
   * 
   * @param hostname the hostname to perform a DNS lookup for
   * @returns string[] the list of resolved IP addresses
   */
  async hostnameLookup(hostname: string): Promise<string[]> {
    const ipAddressListDetails: LookupAddress[] = await lookup(hostname, { all: true })
    const ipAddressList = ipAddressListDetails.map(ipAddressDetails => {
      return ipAddressDetails.address
    })
    return ipAddressList
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
    
    const ipAddressList: string[] = await this.#resolver.resolve4(hostname)
    return ipAddressList
  }

}
