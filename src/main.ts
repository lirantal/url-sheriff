import { URL } from 'url';

export class UrlSheriff {
  #config: object

  constructor(config: object) {
    this.#config = config
  }

  #getParsedUrl(url: string | URL): URL {
    if (typeof url === 'string') {
      return new URL(url)
    }

    if (url instanceof URL) {
      return url
    }

    throw new Error('Invalid URL provided')
  }

  async isSafe(url: string | URL): Promise<boolean> {

    let parsedUrl = this.#getParsedUrl(url)

    if (this.#isPrivateHostname(parsedUrl.hostname)) {
      throw new Error('URL uses a private hostname')
    }

    return true
  }

  #isPrivateHostname(hostname: string): boolean {

    const privateHostnames: string[] = [
      'localhost',
      '127',
      '169.254',
      '10',
      '172.16',
      '192.168',
      '100.64',
    ]

    return privateHostnames.some((privateHostname) => {
      return hostname.startsWith(privateHostname)
    })
  }
}

/**
 * Features to support:
 * 1. add an allow-list of domains or ips that are allowed
 * 1.1. domain list can be string literals or regex to match against
 *
 *
 * Security controls:
 * 1. runs IP address string matching (127.0.0.1 etc)
 * 2. runs hostname string matching (localhost etc)
 * 3. resolves the provided hostname to an IP address and runs the IP address string matching
 * 4. check if IP is a public IP address namespace
 * 5. a check that tests against DNS rebinding attacks
 */
