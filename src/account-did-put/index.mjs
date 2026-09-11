import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand
} from '@aws-sdk/client-dynamodb'

// Overridden only for local development, where DYNAMO_ENDPOINT_URL points at
// a DynamoDB substitute; empty in every deployed environment.
const dynamoClient = new DynamoDBClient(
  process.env.DYNAMO_ENDPOINT_URL ? { endpoint: process.env.DYNAMO_ENDPOINT_URL } : {}
)
const ACCOUNT_TABLE_NAME = process.env.ACCOUNT_TABLE_NAME ?? 'wallet-test'
const AUDIT_TABLE_NAME = process.env.AUDIT_TABLE_NAME ?? 'lcw-admin-audit'

// An Ed25519 did:key is 'z6Mk' followed by 44 base58btc characters. Validated
// strictly because a typo here is not a cosmetic error: the account would be
// handed to a key nobody holds, and neither its owner nor an admin could ever
// sign for it again.
const DID_KEY_PATTERN = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/

const json = (statusCode, body) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
})

const pathEmail = (event) => {
  const raw = event.pathParameters?.email ?? ''
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

export const handler = async (event) => {
  const admin = event.requestContext?.authorizer?.lambda ?? {}
  const email = pathEmail(event)
  if (!email) {
    return json(400, { error: 'Missing email in path.' })
  }

  let did, reason
  try {
    const rawBody = event.isBase64Encoded
      ? Buffer.from(event.body ?? '', 'base64').toString('utf8')
      : event.body
    ;({ did, reason } = JSON.parse(rawBody ?? '{}'))
  } catch {
    return json(400, { error: 'Request body must be valid JSON.' })
  }

  // Stored DIDs may carry a key fragment (did:key:z6Mk...#z6Mk...); both back
  // ends strip it, so store the bare DID.
  const newDid = String(did ?? '').split('#')[0].trim()
  if (!DID_KEY_PATTERN.test(newDid)) {
    return json(400, {
      error: 'did must be an Ed25519 did:key (did:key:z6Mk...).'
    })
  }

  let account
  try {
    ({ Item: account } = await dynamoClient.send(new GetItemCommand({
      TableName: ACCOUNT_TABLE_NAME,
      Key: { email: { S: email } }
    })))
  } catch (error) {
    console.error('Error reading account before DID reset:', error)
    return json(500, { error: 'Failed to read account.' })
  }

  if (!account) {
    return json(404, { error: 'No such account.' })
  }

  const previousDid = account.did?.S
  if (previousDid?.split('#')[0] === newDid) {
    return json(200, { email, did: newDid, unchanged: true })
  }

  // Recorded first, for the same reasons as a deletion, and because this is
  // the more consequential of the two: whoever holds the new key now controls
  // the account and everything in its space. The previous DID is kept so the
  // handover can be undone and so it is always answerable who performed it.
  try {
    await dynamoClient.send(new PutItemCommand({
      TableName: AUDIT_TABLE_NAME,
      Item: {
        targetEmail: { S: email },
        createdAt: { S: new Date().toISOString() },
        action: { S: 'account.did.reset' },
        adminDid: { S: String(admin.adminDid ?? '') },
        adminEmail: { S: String(admin.adminEmail ?? '') },
        detail: {
          S: JSON.stringify({
            previousDid,
            newDid,
            reason: typeof reason === 'string' && reason.trim() ? reason.trim() : undefined
          })
        }
      }
    }))
  } catch (error) {
    console.error('Error recording DID reset:', error)
    return json(500, { error: 'Failed to record the action; the DID was not changed.' })
  }

  try {
    await dynamoClient.send(new UpdateItemCommand({
      TableName: ACCOUNT_TABLE_NAME,
      Key: { email: { S: email } },
      UpdateExpression: 'SET #did = :did',
      ConditionExpression: 'attribute_exists(email)',
      ExpressionAttributeNames: { '#did': 'did' },
      ExpressionAttributeValues: { ':did': { S: newDid } }
    }))
  } catch (error) {
    console.error('Error updating DID:', error)
    return json(500, { error: 'Failed to change the controlling DID.' })
  }

  return json(200, { email, did: newDid, previousDid })
}
