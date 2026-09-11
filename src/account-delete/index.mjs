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
    await dynamoClient.send(new PutItemCommand({
      TableName: AUDIT_TABLE_NAME,
      Item: {
        targetEmail: { S: email },
        createdAt: { S: new Date().toISOString() },
        action: { S: 'account.delete' },
        adminDid: { S: String(admin.adminDid ?? '') },
        adminEmail: { S: String(admin.adminEmail ?? '') },
        detail: { S: JSON.stringify({ removed }) }
      }
    }))
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
    console.error('Error deleting account:', error)
    return json(500, { error: 'Failed to delete the account.' })
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
