import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb'

// Overridden only for local development, where DYNAMO_ENDPOINT_URL points at
// a DynamoDB substitute; empty in every deployed environment.
const dynamoClient = new DynamoDBClient(
  process.env.DYNAMO_ENDPOINT_URL ? { endpoint: process.env.DYNAMO_ENDPOINT_URL } : {}
)
const ACCOUNT_TABLE_NAME = process.env.ACCOUNT_TABLE_NAME ?? 'wallet-test'
const DEFAULT_LIMIT = 50
const MAX_LIMIT = 200

const json = (statusCode, body) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
})

const toAccount = (item) => ({
  email: item.email?.S,
  did: item.did?.S,
  spaceURL: item.spaceURL?.S,
  createdAt: item.CreatedAt?.S
})

// A cursor is just DynamoDB's LastEvaluatedKey, opaque to the client.
const encodeCursor = (key) =>
  key ? Buffer.from(JSON.stringify(key), 'utf8').toString('base64url') : undefined
const decodeCursor = (cursor) =>
  cursor ? JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) : undefined

export const handler = async (event) => {
  const params = event.queryStringParameters ?? {}
  // A negative or non-numeric limit is a client error, not a reason to hand
  // DynamoDB something it will reject with a 500.
  const requested = Number(params.limit)
  const limit = Number.isFinite(requested) && requested > 0
    ? Math.min(Math.floor(requested), MAX_LIMIT)
    : DEFAULT_LIMIT
  const query = (params.q ?? '').trim()

  let exclusiveStartKey
  try {
    exclusiveStartKey = decodeCursor(params.cursor)
  } catch {
    return json(400, { error: 'Invalid cursor.' })
  }

  // The accounts table is keyed by email with no secondary indexes, and it
  // belongs to the lcw-back-end stack - this API deliberately adds none, so
  // any search other than an exact email is a filtered scan.
  const command = new ScanCommand({
    TableName: ACCOUNT_TABLE_NAME,
    Limit: limit,
    ExclusiveStartKey: exclusiveStartKey,
    ...(query
      ? {
          FilterExpression:
            'contains(email, :q) OR contains(did, :q) OR contains(spaceURL, :q)',
          ExpressionAttributeValues: { ':q': { S: query } }
        }
      : {})
  })

  let result
  try {
    result = await dynamoClient.send(command)
  } catch (error) {
    console.error('Error listing accounts:', error)
    return json(500, { error: 'Failed to list accounts.' })
  }

  return json(200, {
    accounts: (result.Items ?? []).map(toAccount),
    // A filtered page can come back empty while more pages remain, so clients
    // must follow the cursor rather than stop at the first empty page.
    nextCursor: encodeCursor(result.LastEvaluatedKey)
  })
}
