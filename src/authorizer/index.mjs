import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb'
import { verifyAdminRequest } from './zcap.mjs'

// Overridden only for local development, where DYNAMO_ENDPOINT_URL points at
// a DynamoDB substitute; empty in every deployed environment.
const dynamoClient = new DynamoDBClient(
  process.env.DYNAMO_ENDPOINT_URL ? { endpoint: process.env.DYNAMO_ENDPOINT_URL } : {}
)
const ADMIN_TABLE_NAME = process.env.ADMIN_TABLE_NAME ?? 'lcw-admin'
const EXPECTED_HOST = process.env.EXPECTED_HOST || undefined

// Looks the signing DID up among the registered admins. The table is keyed by
// email, so the did-index GSI serves this lookup.
async function lookupAdmin (did) {
  const { Items: items = [] } = await dynamoClient.send(new QueryCommand({
    TableName: ADMIN_TABLE_NAME,
    IndexName: 'did-index',
    KeyConditionExpression: '#did = :did',
    ExpressionAttributeNames: { '#did': 'did' },
    ExpressionAttributeValues: { ':did': { S: did } }
  }))
  // One DID, one admin. Two rows here would mean an audit record naming
  // whichever the index happened to return first, so refuse rather than
  // attribute an action to a coin flip. scripts/add-admin.mjs refuses to
  // create the second row, so this is a last line of defence.
  if (items.length > 1) {
    throw new Error(
      `${items.length} admins share ${did}; refusing until that is resolved`
    )
  }
  const item = items[0]
  return item ? { email: item.email?.S, name: item.name?.S } : undefined
}

// HTTP API Lambda authorizer (payload v2, simple responses). A denial is
// { isAuthorized: false }, which API Gateway answers with 403; handlers read
// the admin identity off event.requestContext.authorizer.lambda.
export const handler = async (event) => {
  let admin
  try {
    admin = await verifyAdminRequest(event, lookupAdmin, { expectedHost: EXPECTED_HOST })
  } catch (error) {
    // Logged, not returned: the caller learns only that they were refused.
    console.error('admin zcap verification failed:', error)
    return { isAuthorized: false }
  }

  // Context values must be scalars - no nested objects or arrays.
  return {
    isAuthorized: true,
    context: {
      adminDid: String(admin.did ?? ''),
      adminEmail: String(admin.email ?? ''),
      adminName: String(admin.name ?? '')
    }
  }
}
