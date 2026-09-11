import { securityLoader } from '@interop/security-document-loader'
import { verifyCapabilityInvocation } from '@interop/http-signature-zcap-verify'
import * as didKey from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'

const didKeyDriver = didKey.driver()
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey.from
})

const baseDocumentLoader = securityLoader()

// API Gateway passes headers through with whatever casing the client sent, and
// sam local preserves the original casing, so header reads are case-insensitive.
export function getHeader (headers, name) {
  const match = Object.keys(headers ?? {}).find(
    key => key.toLowerCase() === name.toLowerCase()
  )
  return match === undefined ? undefined : headers[match]
}

// The signature header names the key that signed the request:
//   Signature keyId="did:key:z6Mk...#z6Mk...",headers="...",signature="..."
// That keyId is the caller's only identity claim, and it is the one thing they
// cannot lie about: verification below fails unless they hold its private key.
export function didFromAuthorization (authorization) {
  const keyId = /keyId="([^"]+)"/.exec(authorization ?? '')?.[1]
  return keyId ? keyId.split('#')[0] : undefined
}

// Resolves any urn:zcap:root:<target> to a root capability controlled by the
// given DID. Verification therefore succeeds only for that DID's key.
function rootCapabilityLoader (controller) {
  const loader = baseDocumentLoader.clone()
  loader.setProtocolHandler({
    protocol: 'urn',
    handler: {
      get: async ({ id, url }) => {
        const resolvedUrl = url || id
        const invocationTarget = decodeURIComponent(
          resolvedUrl.split('urn:zcap:root:')[1]
        )
        return {
          '@context': 'https://w3id.org/zcap/v1',
          id: resolvedUrl,
          invocationTarget,
          controller
        }
      }
    }
  })
  return loader.build()
}

// The signature covers the request target exactly as the client sent it, so
// the path has to be reassembled with its query string and with its original
// percent-encoding intact. rawPath/rawQueryString carry both under API
// Gateway; sam local omits rawQueryString, hence the fallback.
export function requestPath (event) {
  const path = event.rawPath ?? event.requestContext?.path ?? event.path ?? ''
  const query = event.rawQueryString ?? new URLSearchParams(
    Object.entries(event.queryStringParameters ?? {})
  ).toString()
  return query ? `${path}?${query}` : path
}

async function getVerifier ({ keyId }) {
  const didDocument = await didKeyDriver.get({ url: keyId })
  const key = await Ed25519VerificationKey.from(didDocument)
  return { verifier: key.verifier(), verificationMethod: didDocument }
}

// Verifies that the request was signed by `controller`'s key, over this exact
// method, host and path. `lookupAdmin` is injected so this stays testable
// without DynamoDB.
export async function verifyAdminRequest (event, lookupAdmin) {
  const headers = event.headers ?? {}
  const method = event.requestContext?.http?.method ?? event.httpMethod
  const host = getHeader(headers, 'Host')
  // Rebuilt from the request's own host and protocol rather than hardcoded, so
  // signatures verify under sam local (http://127.0.0.1:<port>) as well as
  // behind API Gateway.
  const proto = getHeader(headers, 'X-Forwarded-Proto') ?? 'https'
  const url = `${proto}://${host}${requestPath(event)}`

  const did = didFromAuthorization(getHeader(headers, 'Authorization'))
  if (!did) {
    throw new Error('Request carries no signature keyId')
  }

  // An admin is a row in the admin table and nothing else. A wallet account,
  // however it is flagged, can never satisfy this.
  const admin = await lookupAdmin(did)
  if (!admin) {
    throw new Error(`Not a registered admin: ${did}`)
  }

  const result = await verifyCapabilityInvocation({
    url,
    method,
    // The signature is computed over the lowercase header name.
    headers: { ...headers, authorization: getHeader(headers, 'Authorization') },
    suite: new Ed25519Signature2020(),
    getVerifier,
    documentLoader: rootCapabilityLoader(did),
    expectedHost: host,
    expectedAction: method,
    expectedTarget: url,
    expectedRootCapability: 'urn:zcap:root:' + encodeURIComponent(url)
  })

  if (!result.verified) {
    // The reconstructed target is the usual culprit when a genuine signature
    // is refused, so name it. It is public information: the URL, not the key.
    const error = result.error ?? new Error('Capability invocation did not verify')
    error.message = `${error.message} (verifying ${method} ${url})`
    throw error
  }

  return { did, email: admin.email, name: admin.name }
}
