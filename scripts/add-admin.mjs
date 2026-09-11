#!/usr/bin/env node
// Registers, lists and removes admin identities.
//
// There is no admin sign-up endpoint, and deliberately so: an admin is created
// out of band by whoever operates the deployment, never by the console itself.
// Anything else would mean the admin API could grow its own membership.
//
//   node scripts/add-admin.mjs --list
//   node scripts/add-admin.mjs --email you@example.org --did did:key:z6Mk...
//   node scripts/add-admin.mjs --email you@example.org --passphrase 'long passphrase'
//   node scripts/add-admin.mjs --email you@example.org --remove
//
// Prefer --did: the admin generates their own key and hands over only the
// public DID, so the passphrase never leaves their machine. --passphrase is
// for local development, where deriving it here is simply faster.
//
// Local development adds --endpoint-url http://localhost:8000, which also
// creates the table if it is missing. Against real AWS the table belongs to
// the CloudFormation stack and is never created here.
import {
  DynamoDBClient,
  PutItemCommand,
  DeleteItemCommand,
  ScanCommand,
  CreateTableCommand,
  DescribeTableCommand
} from '@aws-sdk/client-dynamodb'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

const DID_KEY_PATTERN = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/

function parseArgs (argv) {
  const args = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (!arg.startsWith('--')) continue
    const name = arg.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) {
      args[name] = true
    } else {
      args[name] = next
      i++
    }
  }
  return args
}

const args = parseArgs(process.argv.slice(2))

const TABLE_NAME = args.table ?? process.env.ADMIN_TABLE_NAME ?? 'lcw-admin'
const REGION = args.region ?? process.env.AWS_REGION ?? 'us-east-1'
const ENDPOINT = args['endpoint-url'] ?? process.env.AWS_ENDPOINT_URL_DYNAMODB
const AUDIT_TABLE_NAME = args['audit-table'] ?? process.env.AUDIT_TABLE_NAME ?? 'lcw-admin-audit'

const client = new DynamoDBClient({
  region: REGION,
  ...(ENDPOINT ? { endpoint: ENDPOINT } : {}),
  // DynamoDB Local accepts any credentials but the SDK insists on having some.
  ...(ENDPOINT
    ? { credentials: { accessKeyId: 'localtest', secretAccessKey: 'localtest' } }
    : {})
})

function fail (message) {
  console.error(message)
  process.exit(1)
}

// Matches the wallet exactly: SHA-256(passphrase) is the 32-byte Ed25519 seed,
// so one passphrase always yields one did:key. See lcw-front-end
// src/lib/login.ts - if that derivation ever changes, this must change with it.
async function didFromPassphrase (passphrase) {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(passphrase)
  )
  const keyPair = await Ed25519VerificationKey.generate({
    seed: new Uint8Array(digest)
  })
  return `did:key:${keyPair.fingerprint()}`
}

// Only ever for local substitutes; deployed tables belong to the stack.
async function ensureLocalTable (definition) {
  if (!ENDPOINT) return
  try {
    await client.send(new DescribeTableCommand({ TableName: definition.TableName }))
    return
  } catch (error) {
    if (error.name !== 'ResourceNotFoundException') throw error
  }
  await client.send(new CreateTableCommand(definition))
  console.log(`Created table ${definition.TableName} at ${ENDPOINT}`)
}

const adminTableDefinition = {
  TableName: TABLE_NAME,
  BillingMode: 'PAY_PER_REQUEST',
  AttributeDefinitions: [
    { AttributeName: 'email', AttributeType: 'S' },
    { AttributeName: 'did', AttributeType: 'S' }
  ],
  KeySchema: [{ AttributeName: 'email', KeyType: 'HASH' }],
  GlobalSecondaryIndexes: [{
    IndexName: 'did-index',
    KeySchema: [{ AttributeName: 'did', KeyType: 'HASH' }],
    Projection: { ProjectionType: 'ALL' }
  }]
}

const auditTableDefinition = {
  TableName: AUDIT_TABLE_NAME,
  BillingMode: 'PAY_PER_REQUEST',
  AttributeDefinitions: [
    { AttributeName: 'targetEmail', AttributeType: 'S' },
    { AttributeName: 'createdAt', AttributeType: 'S' }
  ],
  KeySchema: [
    { AttributeName: 'targetEmail', KeyType: 'HASH' },
    { AttributeName: 'createdAt', KeyType: 'RANGE' }
  ]
}

async function list () {
  const { Items: items = [] } = await client.send(new ScanCommand({
    TableName: TABLE_NAME
  }))
  if (items.length === 0) {
    console.log(`No admins registered in ${TABLE_NAME}.`)
    return
  }
  console.log(`Admins in ${TABLE_NAME}:`)
  for (const item of items) {
    console.log(`  ${item.email?.S}  ${item.did?.S}  (added ${item.createdAt?.S ?? 'unknown'})`)
  }
}

async function remove (email) {
  await client.send(new DeleteItemCommand({
    TableName: TABLE_NAME,
    Key: { email: { S: email } }
  }))
  console.log(`Removed admin ${email} from ${TABLE_NAME}.`)
}

async function add ({ email, did, name }) {
  await client.send(new PutItemCommand({
    TableName: TABLE_NAME,
    Item: {
      email: { S: email },
      did: { S: did },
      createdAt: { S: new Date().toISOString() },
      ...(name ? { name: { S: name } } : {})
    }
  }))
  console.log(`Registered admin ${email}`)
  console.log(`  did: ${did}`)
}

await ensureLocalTable(adminTableDefinition)
await ensureLocalTable(auditTableDefinition)

if (args.list) {
  await list()
  process.exit(0)
}

const email = typeof args.email === 'string' ? args.email.trim() : undefined
if (!email) {
  fail('Usage: add-admin.mjs --email <email> [--did <did:key:...> | --passphrase <passphrase>] [--name <name>] [--remove]')
}

if (args.remove) {
  await remove(email)
  process.exit(0)
}

let did
if (typeof args.did === 'string') {
  did = args.did.split('#')[0].trim()
} else if (typeof args.passphrase === 'string') {
  did = await didFromPassphrase(args.passphrase)
} else {
  fail('Give either --did <did:key:...> or --passphrase <passphrase>.')
}

if (!DID_KEY_PATTERN.test(did)) {
  fail(`Not an Ed25519 did:key: ${did}`)
}

await add({ email, did, name: typeof args.name === 'string' ? args.name : undefined })
