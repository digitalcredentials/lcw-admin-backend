import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand
} from '@aws-sdk/client-dynamodb'
import { verifyHeaderValue } from '@interop/http-digest-header'

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

const getHeader = (headers, name) => {
  const match = Object.keys(headers ?? {}).find(
    (key) => key.toLowerCase() === name.toLowerCase()
  )
  return match === undefined ? undefined : headers[match]
}

// Appends one record. Conditional on the key not existing, so a record can
// never overwrite another; the timestamp is nudged forward on a collision,
// which only happens when one admin acts on one account twice inside a
// millisecond. Returns the timestamp actually written.
async function record({ targetEmail, action, admin, detail }) {
  let createdAt = Date.now()
  for (let attempt = 0; attempt < 5; attempt++) {
    const timestamp = new Date(createdAt).toISOString()
    try {
      await dynamoClient.send(new PutItemCommand({
        TableName: AUDIT_TABLE_NAME,
        Item: {
          targetEmail: { S: targetEmail },
          createdAt: { S: timestamp },
          // One partition for the whole log, so recent-index can serve it
          // newest-first across every account.
          log: { S: 'all' },
          action: { S: action },
          adminDid: { S: admin.adminDid },
          adminEmail: { S: admin.adminEmail },
          detail: { S: JSON.stringify(detail) }
        },
        ConditionExpression: 'attribute_not_exists(targetEmail) AND attribute_not_exists(createdAt)'
      }))
      return timestamp
    } catch (error) {
      if (error.name !== 'ConditionalCheckFailedException') {
        throw error
      }
      createdAt += 1
    }
  }
  throw new Error('Could not append a unique audit record')
}

export const handler = async (event) => {
  const context = event.requestContext?.authorizer?.lambda ?? {}
  const admin = {
    adminDid: String(context.adminDid ?? ''),
    adminEmail: String(context.adminEmail ?? '')
  }
  // Nothing destructive happens unattributed. An empty identity means the
  // authorizer context did not arrive, which is a misconfiguration, not a
  // request to be honoured with an anonymous audit record.
  if (!admin.adminDid) {
    console.error('Refusing a DID reset: the request carries no admin identity')
    return json(500, { error: 'Could not establish who is making this request.' })
  }

  const email = pathEmail(event)
  if (!email) {
    return json(400, { error: 'Missing email in path.' })
  }

  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body ?? '', 'base64').toString('utf8')
    : (event.body ?? '')

  // The signature covers a digest of the body, but the authorizer is never
  // given the body to check it against - an HTTP API authorizer event carries
  // headers only. So the body is authenticated here, against the digest the
  // caller signed. Without this, a captured set of valid headers could be
  // replayed with a different DID in the body, and the account handed to the
  // replayer under the original admin's name.
  const digest = getHeader(event.headers, 'digest')
  if (!digest) {
    console.error(`Refusing a DID reset for ${email}: request carried no signed body digest`)
    return json(401, { error: 'Request body must be covered by a signed digest.' })
  }
  try {
    const { verified } = await verifyHeaderValue({
      data: Buffer.from(rawBody, 'utf8'),
      headerValue: digest
    })
    if (!verified) {
      console.error(`Refusing a DID reset for ${email}: body does not match the signed digest`)
      return json(401, { error: 'Request body does not match its signed digest.' })
    }
  } catch (error) {
    console.error(`Refusing a DID reset for ${email}: digest could not be verified:`, error)
    return json(401, { error: 'Request body does not match its signed digest.' })
  }

  let did, reason
  try {
    ({ did, reason } = JSON.parse(rawBody || '{}'))
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

  const trimmedReason =
    typeof reason === 'string' && reason.trim() ? reason.trim() : undefined

  // Recorded first, for the same reasons as a deletion, and because this is
  // the more consequential of the two: whoever holds the new key now controls
  // the account and everything in its space. The previous DID is kept so the
  // handover can be undone and so it is always answerable who performed it.
  try {
    await record({
      targetEmail: email,
      action: 'account.did.reset',
      admin,
      detail: { previousDid, newDid, reason: trimmedReason }
    })
  } catch (error) {
    console.error('Error recording DID reset:', error)
    return json(500, { error: 'Failed to record the action; the DID was not changed.' })
  }

  try {
    await dynamoClient.send(new UpdateItemCommand({
      TableName: ACCOUNT_TABLE_NAME,
      Key: { email: { S: email } },
      UpdateExpression: 'SET #did = :did',
      // Conditional on the DID that was read and recorded as the previous one.
      // Without this, a reset racing another change would overwrite a DID the
      // log does not mention, and the recorded undo would restore the wrong
      // key.
      ConditionExpression: previousDid === undefined
        ? 'attribute_exists(email) AND attribute_not_exists(#did)'
        : 'attribute_exists(email) AND #did = :previousDid',
      ExpressionAttributeNames: { '#did': 'did' },
      ExpressionAttributeValues: {
        ':did': { S: newDid },
        ...(previousDid === undefined ? {} : { ':previousDid': { S: previousDid } })
      }
    }))
  } catch (error) {
    const raced = error.name === 'ConditionalCheckFailedException'
    console.error('Error updating DID:', error)
    // The record above says this reset happened. It did not, so say so in the
    // log as well as in the response - the log cannot be edited, only added to.
    try {
      await record({
        targetEmail: email,
        action: 'account.did.reset.aborted',
        admin,
        detail: {
          newDid,
          reason: trimmedReason,
          why: raced
            ? 'The account changed between reading it and writing it; nothing was changed.'
            : 'The write failed; nothing was changed.'
        }
      })
    } catch (recordError) {
      console.error('Error recording the aborted DID reset:', recordError)
    }
    return json(raced ? 409 : 500, {
      error: raced
        ? 'This account changed while the reset was in flight. Nothing was changed; reload and try again.'
        : 'Failed to change the controlling DID.'
    })
  }

  return json(200, { email, did: newDid, previousDid })
}
