import { PutItemCommand } from '@aws-sdk/client-dynamodb'

// Every record carries the same partition value so that recent-index holds the
// whole log in one time-ordered partition. A writer that omitted it would keep
// working - the record would land in the table and show under the account -
// while vanishing from the global feed, so this literal lives in exactly one
// place and every writer goes through appendRecord.
export const AUDIT_LOG_PARTITION = 'all'

const MAX_TIMESTAMP_ATTEMPTS = 5

const sameRecord = (existing, item) =>
  existing?.action?.S === item.action.S &&
  existing?.adminDid?.S === item.adminDid.S &&
  existing?.adminEmail?.S === item.adminEmail.S &&
  existing?.detail?.S === item.detail.S

/**
 * Appends one record to the audit log and returns the timestamp written.
 *
 * The write is conditional on its key not already existing, which is what
 * makes the log append-only in fact: a record can neither be altered nor
 * silently overwritten. Two writes landing in the same millisecond are
 * separated by nudging the timestamp forward.
 *
 * A conditional failure is not on its own evidence of a collision. The AWS SDK
 * retries a PutItem whose response was lost, and that retry fails its own
 * condition against the item it just wrote - which, treated as a collision,
 * would append a second copy of one action to a log that can never be
 * corrected. ReturnValuesOnConditionCheckFailure hands back the item that is
 * already there, so an identical one is recognised as this same write
 * arriving twice.
 */
export async function appendRecord(client, tableName, { targetEmail, action, admin, detail }) {
  let createdAt = Date.now()

  for (let attempt = 0; attempt < MAX_TIMESTAMP_ATTEMPTS; attempt++) {
    const timestamp = new Date(createdAt).toISOString()
    const item = {
      targetEmail: { S: targetEmail },
      createdAt: { S: timestamp },
      log: { S: AUDIT_LOG_PARTITION },
      action: { S: action },
      adminDid: { S: admin.adminDid },
      adminEmail: { S: admin.adminEmail },
      detail: { S: JSON.stringify(detail ?? {}) }
    }

    try {
      await client.send(new PutItemCommand({
        TableName: tableName,
        Item: item,
        ConditionExpression: 'attribute_not_exists(targetEmail)',
        ReturnValuesOnConditionCheckFailure: 'ALL_OLD'
      }))
      return timestamp
    } catch (error) {
      if (error.name !== 'ConditionalCheckFailedException') {
        throw error
      }
      if (sameRecord(error.Item, item)) {
        // This exact record is already there: a retry of our own write.
        return timestamp
      }
      createdAt += 1
    }
  }

  throw new Error('Could not append a unique audit record')
}
