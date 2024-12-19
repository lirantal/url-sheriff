#!/usr/bin/env node
import { debuglog } from 'node:util'
import { add } from '../main.ts'

const debug = debuglog('url-sheriff')

async function init () {
    const sum = await add(1,2)
    debug(sum.toString())
}

init()