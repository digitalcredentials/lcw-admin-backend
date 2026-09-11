import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  DeleteItemCommand
} from '@aws-sdk/client-dynamodb'

// Overridden only for local development, where DYNAMO_ENDPOINT_URL points at
// a DynamoDB substitute; empty in every deployed environment.
const dynamoClient = new DynamoDBClient(
  process.env.DYNAMO_ENDPOINT_URL ? { endpoint: process.env.DYNAMO_ENDPOINT_URL } : {}
)
const ACCOUNT_TABLE_NAME = process.env.ACCOUNT_TABLE_NAME ?? 'wallet-test'
const AUDIT_TABLE_NAME = process.env.AUDIT_TABLE_NAME ?? 'lcw-admin-audit'

// Appends one record. Conditional on the key not existing, so a record can
// never overwrite another; the timestamp is nudged forward on a collision,
// which only happens when one admin acts on one account twice inside a
// millisecond.
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
  const context = event.requestContext?.authorizer?.lambda ?? {}
  const admin = {
    adminDid: String(context.adminDid ?? ''),
    adminEmail: String(context.adminEmail ?? '')
  }
  // Nothing destructive happens unattributed. An empty identity means the
  // authorizer context did not arrive, which is a misconfiguration, not a
  // request to be honoured with an anonymous audit record.
  if (!admin.adminDid) {
    console.error('Refusing a deletion: the request carries no admin identity')
    return json(500, { error: 'Could not establish who is making this request.' })
  }

  const email = pathEmail(event)
  if (!email) {
    return json(400, { error: 'Missing email in path.' })
  }

  let account
  try {
    ({ Item: account } = await dynamoClient.send(new GetItemCommand({
      TableName: ACCOUNT_TABLE_NAME,
      Key: { email: { S: email } }
    })))
  } catch (error) {
    console.error('Error reading account before delete:', error)
    return json(500, { error: 'Failed to read account.' })
  }

  if (!account) {
    return json(404, { error: 'No such account.' })
  }

  const removed = {
    email: account.email?.S,
    did: account.did?.S,
    spaceURL: account.spaceURL?.S,
    createdAt: account.CreatedAt?.S
  }

  // Recorded before the row is removed, and the record carries the whole row.
  // Two consequences, both deliberate: an audit failure aborts the deletion
  // rather than losing the trace of it, and the record is everything needed to
  // put the account back. The cost is that a delete which then fails leaves a
  // record of an action that did not complete - the response says so, and the
  // row is still there to prove it.
  try {
    await record({
      targetEmail: email,
      action: 'account.delete',
      admin,
      detail: { removed }
    })
  } catch (error) {
    console.error('Error recording deletion:', error)
    return json(500, { error: 'Failed to record the action; nothing was deleted.' })
  }

  try {
    await dynamoClient.send(new DeleteItemCommand({
      TableName: ACCOUNT_TABLE_NAME,
      Key: { email: { S: email } },
      ConditionExpression: 'attribute_exists(email)'
    }))
  } catch (error) {
    const raced = error.name === 'ConditionalCheckFailedException'
    console.error('Error deleting account:', error)
    // The record above says this deletion happened. It did not, so say so in
    // the log as well as in the response - the log cannot be edited, only
    // added to.
    try {
      await record({
        targetEmail: email,
        action: 'account.delete.aborted',
        admin,
        detail: {
          why: raced
            ? 'The account was already gone when the deletion was applied; nothing was changed.'
            : 'The write failed; nothing was changed.'
        }
      })
    } catch (recordError) {
      console.error('Error recording the aborted deletion:', recordError)
    }
    return json(raced ? 409 : 500, {
      error: raced
        ? 'This account was already deleted. Nothing was changed.'
        : 'Failed to delete the account.'
    })
  }

  // The account's Wallet Attached Storage space is untouched: this API holds no
  // S3 permission at all. The space becomes unreachable only because the WAS
  // authorizer resolves its controller through this row - putting the row back
  // restores access to it intact.
  return json(200, {
    deleted: removed,
    note: 'The account row was removed. The space and its contents were not touched; restoring this row restores access to them.'
  })
}
