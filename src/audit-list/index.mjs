import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb'

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

export const handler = async (event) => {
  const limit = Math.min(
    Number(event.queryStringParameters?.limit) || DEFAULT_LIMIT,
    MAX_LIMIT
  )

  // The table is partitioned by the account acted on, which makes one
  // account's history a query but the global feed a scan. At the scale this
  // console is for - a handful of admins acting occasionally - that is the
  // honest trade: no extra index on a log nobody queries in bulk.
  let items
  try {
    const result = await dynamoClient.send(new ScanCommand({
      TableName: AUDIT_TABLE_NAME
    }))
    items = result.Items ?? []
  } catch (error) {
    console.error('Error listing audit records:', error)
    return json(500, { error: 'Failed to list admin actions.' })
  }

  const entries = items
    .map((entry) => ({
      targetEmail: entry.targetEmail?.S,
      createdAt: entry.createdAt?.S,
      action: entry.action?.S,
      adminDid: entry.adminDid?.S,
      adminEmail: entry.adminEmail?.S,
      detail: entry.detail?.S ? JSON.parse(entry.detail.S) : undefined
    }))
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
    .slice(0, limit)

  return json(200, { entries })
}
