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
// A cursor is opaque to clients, so anything that is not the shape DynamoDB
// handed out is a client error. Parsing alone is not enough of a check: '1'
// and '[]' are valid JSON and would reach DynamoDB, which rejects them as a
// server-side validation failure and so would be reported as a 500.
const decodeCursor = (cursor) => {
  if (!cursor) {
    return undefined
  }
  const key = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'))
  const valid =
    typeof key === 'object' && key !== null && !Array.isArray(key) &&
    Object.values(key).every(
      (value) => typeof value === 'object' && value !== null && typeof value.S === 'string'
    )
  if (!valid) {
    throw new TypeError('Cursor is not a DynamoDB key')
  }
  return key
}

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
    // Math.max keeps a fraction below 1 from flooring to 0, which DynamoDB
    // rejects outright - the 500 this parsing exists to avoid.
    ? Math.min(Math.max(Math.floor(requested), 1), MAX_LIMIT)
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
