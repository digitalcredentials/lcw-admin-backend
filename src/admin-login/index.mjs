// Login is an authorized whoami. The authorizer has already verified that the
// caller holds the key of a DID registered in the admin table, so there is
// nothing left to check and nothing to issue: no token, no cookie, no session.
// Every later request is signed exactly like this one.
const json = (statusCode, body) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
})

export const handler = async (event) => {
  const admin = event.requestContext?.authorizer?.lambda ?? {}
  return json(200, {
    verified: true,
    did: admin.adminDid,
    email: admin.adminEmail,
    name: admin.adminName || undefined
  })
}
