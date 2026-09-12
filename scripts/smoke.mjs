#!/usr/bin/env node
// Exercises every admin route against a running API, signing each request as a
// registered admin. Intended for the local stack:
//
//   node scripts/smoke.mjs --passphrase 'admin-secret-seed-that-is-long-e'
//
// It seeds a throwaway wallet account directly in DynamoDB, then reads,
// re-keys and deletes it through the API. It never touches accounts it did not
// create, so it is safe to run alongside the wallet's own local stack.
import '@interop/http-client'
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import { createHeaderValue } from '@interop/http-digest-header'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb'

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, arg, i, all) => {
    if (arg.startsWith('--')) pairs.push([arg.slice(2), all[i + 1]?.startsWith('--') === false ? all[i + 1] : true])
    return pairs
  }, [])
)

const BASE = (args.base ?? 'http://localhost:3002').replace(/\/+$/, '')
const ENDPOINT = args['endpoint-url'] ?? 'http://localhost:8000'
const ACCOUNT_TABLE = args['account-table'] ?? 'wallet-test'
const PASSPHRASE = args.passphrase ?? 'admin-secret-seed-that-is-long-e'
const TEST_EMAIL = args.email ?? 'smoke-test@example.org'

const dynamo = new DynamoDBClient({
  region: 'us-east-1',
  endpoint: ENDPOINT,
  credentials: { accessKeyId: 'localtest', secretAccessKey: 'localtest' }
})

async function keyFromPassphrase (passphrase) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(passphrase))
  const keyPair = await Ed25519VerificationKey.generate({ seed: new Uint8Array(digest) })
  keyPair.controller = `did:key:${keyPair.fingerprint()}`
  keyPair.id = `${keyPair.controller}#${keyPair.fingerprint()}`
  return keyPair
}

const adminKey = await keyFromPassphrase(PASSPHRASE)
// A second key, held by nobody the admin table knows about.
const strangerKey = await keyFromPassphrase('not-an-admin-passphrase-at-all!!')
// Stands in for the account owner's new key after a reset.
const newOwnerKey = await keyFromPassphrase('the accounts brand new passphrase')
// The key someone replaying a captured request would try to substitute.
const attackerKey = await keyFromPassphrase('the key an attacker would swap in')

// `sendInstead` swaps the body after signing, which is what an attacker who
// captured a valid set of headers would do. The signed digest covers the
// original body, so the swap has to be refused.
async function call (method, path, { json, key = adminKey, sendInstead } = {}) {
  const url = `${BASE}${path}`
  const headers = await signCapabilityInvocation({
    url,
    method,
    headers: { host: new URL(url).host },
    ...(json ? { json } : {}),
    capabilityAction: method,
    invocationSigner: key.signer()
  })
  const sentBody = sendInstead ?? json
  const response = await fetch(url, {
    method,
    headers: { ...headers, ...(json ? { 'content-type': 'application/json' } : {}) },
    ...(sentBody ? { body: JSON.stringify(sentBody) } : {})
  })
  const text = await response.text()
  let body
  try { body = JSON.parse(text) } catch { body = text }
  return { status: response.status, body }
}

// '@' and '+' are legal in a URL path segment, and both ends have to agree on
// the literal bytes because the signature covers the request target. Leaving
// them unencoded is what makes that agreement hold: API Gateway hands the
// authorizer the path exactly as sent, while sam local decodes it first, so an
// encoded '@' verifies deployed and fails locally. Anything genuinely unsafe
// is still encoded.
const pathSegment = (email) =>
  encodeURIComponent(email).replace(/%40/g, '@').replace(/%2B/gi, '+')

let failures = 0
function check (name, condition, detail) {
  console.log(`${condition ? '  ok  ' : 'FAIL  '}${name}`)
  if (!condition) {
    failures++
    if (detail !== undefined) console.log(`        ${JSON.stringify(detail)}`)
  }
}

console.log(`Admin DID: ${adminKey.controller}`)
console.log(`Against:   ${BASE}\n`)

// Seed the throwaway account directly: creating wallet accounts is not
// something the admin API can do, by design.
await dynamo.send(new PutItemCommand({
  TableName: ACCOUNT_TABLE,
  Item: {
    email: { S: TEST_EMAIL },
    did: { S: strangerKey.controller },
    spaceURL: { S: 'http://localhost:3000/space/dcc-was-smoke-test' },
    CreatedAt: { S: new Date().toISOString() }
  }
}))
console.log(`Seeded ${TEST_EMAIL}\n`)

// A body, even an empty one: the authorizer requires body-carrying methods to
// sign a digest, so an unsigned-body POST is refused by design.
const login = await call('POST', '/login', { json: {} })
check('POST /login identifies the admin', login.status === 200 && login.body.did === adminKey.controller, login)

// Signed for the same target but with no body, then replayed with one. The
// signature cannot cover a digest it never had, so the authorizer refuses it
// before any handler sees it.
const stripped = await (async () => {
  const url = `${BASE}/accounts/${pathSegment(TEST_EMAIL)}/did`
  const headers = await signCapabilityInvocation({
    url,
    method: 'PUT',
    headers: { host: new URL(url).host },
    capabilityAction: 'PUT',
    invocationSigner: adminKey.signer()
  })
  const body = JSON.stringify({ did: attackerKey.controller })
  const digest = await createHeaderValue({ data: new TextEncoder().encode(body) })
  const response = await fetch(url, { method: 'PUT', headers: { ...headers, digest }, body })
  return response.status
})()
check('a body added to a signature that never covered one is refused', stripped === 403, stripped)

const stranger = await call('GET', '/accounts', { key: strangerKey })
check('a non-admin is refused', stranger.status === 403, stranger)

// 401, not 403: with no Authorization header there is no identity source, so
// the gateway refuses before the authorizer is ever invoked.
const unsigned = await fetch(`${BASE}/accounts`)
check('an unsigned request is refused', unsigned.status === 401, unsigned.status)

const list = await call('GET', '/accounts')
check('GET /accounts lists accounts', list.status === 200 && Array.isArray(list.body.accounts), list)
check('the seeded account is listed', (list.body.accounts ?? []).some(a => a.email === TEST_EMAIL), list.body)

const search = await call('GET', '/accounts?q=smoke-test')
check('GET /accounts?q= filters', search.status === 200 && (search.body.accounts ?? []).every(a =>
  `${a.email}${a.did}${a.spaceURL}`.includes('smoke-test')), search)

const got = await call('GET', `/accounts/${pathSegment(TEST_EMAIL)}`)
check('GET /accounts/{email} reads one account', got.status === 200 && got.body.account?.did === strangerKey.controller, got)

const badDid = await call('PUT', `/accounts/${pathSegment(TEST_EMAIL)}/did`, { json: { did: 'did:key:nonsense' } })
check('a malformed DID is refused', badDid.status === 400, badDid)

// The authorizer is given headers but never the body, so the body has to be
// authenticated by the handler against the digest the admin signed. Without
// that, these captured headers would re-key the account to whoever replayed
// them, recorded against the admin who signed.
const tampered = await call('PUT', `/accounts/${pathSegment(TEST_EMAIL)}/did`, {
  json: { did: newOwnerKey.controller, reason: 'legitimate' },
  sendInstead: { did: attackerKey.controller, reason: 'swapped in transit' }
})
check('a body swapped after signing is refused', tampered.status === 401, tampered)

const afterTamper = await dynamo.send(new GetItemCommand({
  TableName: ACCOUNT_TABLE, Key: { email: { S: TEST_EMAIL } }
}))
check('the tampered request changed nothing',
  afterTamper.Item?.did?.S === strangerKey.controller, afterTamper.Item?.did?.S)

const reset = await call('PUT', `/accounts/${pathSegment(TEST_EMAIL)}/did`, {
  json: { did: newOwnerKey.controller, reason: 'smoke test' }
})
check('PUT /accounts/{email}/did resets the DID', reset.status === 200 && reset.body.did === newOwnerKey.controller, reset)

const afterReset = await dynamo.send(new GetItemCommand({
  TableName: ACCOUNT_TABLE, Key: { email: { S: TEST_EMAIL } }
}))
check('the table shows the new DID', afterReset.Item?.did?.S === newOwnerKey.controller, afterReset.Item)

const history = await call('GET', `/accounts/${pathSegment(TEST_EMAIL)}`)
check('the reset is recorded against the account', (history.body.history ?? []).some(
  h => h.action === 'account.did.reset' && h.adminDid === adminKey.controller &&
       h.detail?.previousDid === strangerKey.controller), history.body.history)

const deleted = await call('DELETE', `/accounts/${pathSegment(TEST_EMAIL)}`)
check('DELETE /accounts/{email} removes the row', deleted.status === 200 && deleted.body.deleted?.email === TEST_EMAIL, deleted)

const afterDelete = await dynamo.send(new GetItemCommand({
  TableName: ACCOUNT_TABLE, Key: { email: { S: TEST_EMAIL } }
}))
check('the row is gone', afterDelete.Item === undefined, afterDelete.Item)

const gone = await call('GET', `/accounts/${pathSegment(TEST_EMAIL)}`)
check('a deleted account still has its history', gone.status === 404 && (gone.body.history ?? []).some(
  h => h.action === 'account.delete' && h.detail?.removed?.spaceURL), gone.body)

const audit = await call('GET', '/audit')
check('GET /audit lists both actions newest first', audit.status === 200 &&
  audit.body.entries?.[0]?.action === 'account.delete' &&
  audit.body.entries?.[1]?.action === 'account.did.reset', audit.body.entries?.slice(0, 2))

// Paged through the time-ordered index, so "newest first" holds across pages
// rather than only within one.
const firstPage = await call('GET', '/audit?limit=1')
check('GET /audit pages, newest first', firstPage.status === 200 &&
  firstPage.body.entries?.length === 1 &&
  firstPage.body.entries[0].action === 'account.delete' &&
  Boolean(firstPage.body.nextCursor), firstPage.body)

const secondPage = await call('GET', `/audit?limit=1&cursor=${encodeURIComponent(firstPage.body.nextCursor ?? '')}`)
check('the next page continues where the first left off', secondPage.status === 200 &&
  secondPage.body.entries?.[0]?.action === 'account.did.reset', secondPage.body.entries)

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) failed.`)
process.exit(failures === 0 ? 0 : 1)
