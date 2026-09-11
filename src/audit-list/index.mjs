import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb'

// Overridden only for local development, where DYNAMO_ENDPOINT_URL points at
// a DynamoDB substitute; empty in every deployed environment.
const dynamoClient = new DynamoDBClient(
  process.env.DYNAMO_ENDPOINT_URL ? { endpoint: process.env.DYNAMO_ENDPOINT_URL } : {}
)
const AUDIT_TABLE_NAME = process.env.AUDIT_TABLE_NAME ?? 'lcw-admin-audit'
const DEFAULT_LIMIT = 100
const MAX_LIMIT = 500

const json = (statusCode, body) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
})

const encodeCursor = (key) =>
  key ? Buffer.from(JSON.stringify(key), 'utf8').toString('base64url') : undefined
const decodeCursor = (cursor) =>
  cursor ? JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) : undefined

// A record whose detail is unreadable is still a record of something an admin
// did, and is more important to show than to parse. Never let one malformed
// row take the whole log down with it.
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
  const params = event.queryStringParameters ?? {}
  const requested = Number(params.limit)
  const limit = Number.isFinite(requested) && requested > 0
    ? Math.min(Math.floor(requested), MAX_LIMIT)
    : DEFAULT_LIMIT

  let exclusiveStartKey
  try {
    exclusiveStartKey = decodeCursor(params.cursor)
  } catch {
    return json(400, { error: 'Invalid cursor.' })
  }

  // Queried through recent-index, whose single partition holds the whole log
  // ordered by time. A Scan could not do this: it would return an arbitrary
  // page, and sorting that page would report "newest first" while quietly
  // omitting more recent records than the ones shown.
  let result
  try {
    result = await dynamoClient.send(new QueryCommand({
      TableName: AUDIT_TABLE_NAME,
      IndexName: 'recent-index',
      KeyConditionExpression: '#log = :log',
      ExpressionAttributeNames: { '#log': 'log' },
      ExpressionAttributeValues: { ':log': { S: 'all' } },
      ScanIndexForward: false,
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey
    }))
  } catch (error) {
    console.error('Error listing audit records:', error)
    return json(500, { error: 'Failed to list admin actions.' })
  }

  return json(200, {
    entries: (result.Items ?? []).map((entry) => ({
      targetEmail: entry.targetEmail?.S,
      createdAt: entry.createdAt?.S,
      action: entry.action?.S,
      adminDid: entry.adminDid?.S,
      adminEmail: entry.adminEmail?.S,
      detail: parseDetail(entry.detail?.S)
    })),
    nextCursor: encodeCursor(result.LastEvaluatedKey)
  })
}
