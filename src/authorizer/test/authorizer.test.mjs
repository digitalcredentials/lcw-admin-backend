// Runs the authorizer in-process against real signed invocations, with the
// admin table mocked.
//
//   cd src/authorizer && npm install && npm test
import { test } from 'node:test'
import assert from 'node:assert/strict'
import '@interop/http-client'
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { handler } from '../index.mjs'
import { didFromAuthorization, verifyAdminRequest } from '../zcap.mjs'

const HOST = 'admin-api.example.org'
const ADMIN_EMAIL = 'admin@example.org'

// A did:key whose private key this test holds, standing in for an admin's.
const key = await Ed25519VerificationKey.generate()
const did = `did:key:${key.fingerprint()}`
key.id = `${did}#${key.fingerprint()}`
key.controller = did

const ddbMock = mockClient(DynamoDBClient)

// Registers `registeredDid` as the only admin; omit it for an empty table.
// The fake honours the key condition, because which DID is being looked up is
// the whole question the authorizer asks of this table.
function withAdmin (registeredDid) {
  ddbMock.reset()
  ddbMock.on(QueryCommand).callsFake((input) => {
    const queried = input.ExpressionAttributeValues?.[':did']?.S
    return queried && queried === registeredDid
      ? { Items: [{ email: { S: ADMIN_EMAIL }, did: { S: registeredDid } }] }
      : { Items: [] }
  })
}

const event = ({ path, method = 'GET', headers = {} }) => ({
  rawPath: path,
  headers: { host: HOST, ...headers },
  requestContext: { http: { method } }
})

// Signs an invocation of `path`, then presents it at `presentedPath` - the two
// differ only when the test is a replay against another route.
async function signedEvent ({ path, method = 'GET', presentedPath = path }) {
  const headers = await signCapabilityInvocation({
    url: `https://${HOST}${path}`,
    method,
    headers: { host: HOST },
    capabilityAction: method,
    invocationSigner: key.signer()
  })
  return event({ path: presentedPath, method, headers })
}

test('parses the signing DID out of the signature keyId', () => {
  assert.equal(
    didFromAuthorization(`Signature keyId="${key.id}",headers="(request-target)",signature="x"`),
    did
  )
  assert.equal(didFromAuthorization(undefined), undefined)
  assert.equal(didFromAuthorization('Signature headers="(request-target)"'), undefined)
})

test('admits a registered admin who signed the request', async () => {
  withAdmin(did)
  const result = await handler(await signedEvent({ path: '/accounts' }))
  assert.equal(result.isAuthorized, true)
  assert.equal(result.context.adminDid, did)
  assert.equal(result.context.adminEmail, ADMIN_EMAIL)
})

test('refuses a correctly signed request from a DID that is not an admin', async () => {
  withAdmin()
  const result = await handler(await signedEvent({ path: '/accounts' }))
  assert.equal(result.isAuthorized, false)
})

// Another admin existing is not authorization to act as them.
test('refuses a signed request when only somebody else is an admin', async () => {
  withAdmin('did:key:z6MkfDLjE5Kip9E7YRitEbrNAcCYi2AviAY8Ny7hoYnCSgav')
  const result = await handler(await signedEvent({ path: '/accounts' }))
  assert.equal(result.isAuthorized, false)
})

// Membership is decided by the keyId, so this is the attack that matters:
// sign with a key you hold, then claim a registered admin's keyId. The lookup
// succeeds and verification is what refuses it.
test('refuses a request that claims a registered admin keyId it cannot sign for', async () => {
  const registered = 'did:key:z6MkfDLjE5Kip9E7YRitEbrNAcCYi2AviAY8Ny7hoYnCSgav'
  withAdmin(registered)
  const signed = await signedEvent({ path: '/accounts' })
  const authorization = signed.headers.authorization ?? signed.headers.Authorization
  const forged = authorization.replace(/keyId="[^"]+"/, `keyId="${registered}#${registered.slice('did:key:'.length)}"`)
  signed.headers.authorization = forged
  delete signed.headers.Authorization
  const result = await handler(signed)
  assert.equal(result.isAuthorized, false)
})

test('refuses an unsigned request', async () => {
  withAdmin(did)
  const result = await handler(event({ path: '/accounts' }))
  assert.equal(result.isAuthorized, false)
})

// Without a pinned host, the target is built from the caller's own Host header
// and the host check compares that header to itself - so a signature made for
// another deployment would be accepted here.
test('refuses a request signed for a different deployment when the host is pinned', async () => {
  const signed = await signedEvent({ path: '/accounts' })
  const lookup = async () => ({ email: ADMIN_EMAIL })

  await assert.rejects(
    verifyAdminRequest(signed, lookup, { expectedHost: 'other-api.example.org' }),
    /is not other-api\.example\.org/
  )
  // ...and the same request is fine against the host it was pinned to.
  const admitted = await verifyAdminRequest(signed, lookup, { expectedHost: HOST })
  assert.equal(admitted.did, did)
})

// An action has to be attributable to one person. Two admins sharing a key
// would make every record written by it ambiguous.
test('refuses a DID that is registered to more than one admin', async () => {
  ddbMock.reset()
  ddbMock.on(QueryCommand).resolves({
    Items: [
      { email: { S: 'one@example.org' }, did: { S: did } },
      { email: { S: 'two@example.org' }, did: { S: did } }
    ]
  })
  const result = await handler(await signedEvent({ path: '/accounts' }))
  assert.equal(result.isAuthorized, false)
})

// The reason the authorizer result cache is disabled: a signature authorizes
// one request, not the caller.
test('refuses a signature replayed against a different route', async () => {
  withAdmin(did)
  const result = await handler(await signedEvent({
    path: '/accounts',
    presentedPath: '/accounts/someone@example.org'
  }))
  assert.equal(result.isAuthorized, false)
})

test('refuses a signature replayed with a different method', async () => {
  withAdmin(did)
  const signed = await signedEvent({ path: '/accounts/x@example.org', method: 'GET' })
  signed.requestContext.http.method = 'DELETE'
  const result = await handler(signed)
  assert.equal(result.isAuthorized, false)
})
