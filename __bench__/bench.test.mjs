import { Resolver, lookup } from 'node:dns/promises'
import { Suite, chartReport } from 'bench-node'

const suite = new Suite({
  reporter: chartReport
})

const hostname = 'snyk.io'

suite.add('Using resolve4', async () => {
  const resolver = new Resolver()
  const ipAddressList = await resolver.resolve4(hostname)
  return ipAddressList
})

suite.add('Using lookup', async () => {
  const ipAddressList = await lookup(hostname)
  return ipAddressList
})

suite.add('Using resolve4 with custom DNS servers', async () => {
  const resolver = new Resolver()
  resolver.setServers(['8.8.8.8', '1.1.1.1'])
  const ipAddressList = await resolver.resolve4(hostname)
  return ipAddressList
})

await suite.run()
