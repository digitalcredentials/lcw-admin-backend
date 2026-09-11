import { DynamoDBClient, GetItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb'

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

// API Gateway hands path parameters over already decoded, but an email
// containing a '+' survives a second decode unharmed, and sam local is less
// consistent, so decode defensively.
const pathEmail = (event) => {
  const raw = event.pathParameters?.email ?? ''
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

// A record whose detail is unreadable is still a record of something an admin
// did, and is more important to show than to parse.
function parseDetail(value) {
  if (!value) {
    return undefined
  }
  try {
    return JSON.parse(value)
  } catch {
    return { unparsed: value }
  }
}

export const handler = async (event) => {
  const email = pathEmail(event)
  if (!email) {
    return json(400, { error: 'Missing email in path.' })
  }

  let account, history
  try {
    const [accountResult, historyResult] = await Promise.all([
      dynamoClient.send(new GetItemCommand({
        TableName: ACCOUNT_TABLE_NAME,
        Key: { email: { S: email } }
      })),
      // Newest first. An account's whole history is one query because the
      // audit table is keyed by the account acted on.
      dynamoClient.send(new QueryCommand({
        TableName: AUDIT_TABLE_NAME,
        KeyConditionExpression: 'targetEmail = :email',
        ExpressionAttributeValues: { ':email': { S: email } },
        ScanIndexForward: false,
        Limit: 50
      }))
    ])
    account = accountResult.Item
    history = historyResult.Items ?? []
  } catch (error) {
    console.error('Error reading account:', error)
    return json(500, { error: 'Failed to read account.' })
  }

  // A deleted account still has a history, and that history holds the row that
  // was removed - which is what makes a deletion reversible. So a missing
  // account is reported with its history rather than as a bare 404.
  return json(account ? 200 : 404, {
    account: account
      ? {
          email: account.email?.S,
          did: account.did?.S,
          spaceURL: account.spaceURL?.S,
          createdAt: account.CreatedAt?.S
        }
      : null,
    history: history.map((entry) => ({
      createdAt: entry.createdAt?.S,
      action: entry.action?.S,
      adminDid: entry.adminDid?.S,
      adminEmail: entry.adminEmail?.S,
      detail: parseDetail(entry.detail?.S)
    }))
  })
}
