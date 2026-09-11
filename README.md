# LCW Admin API

Administration of **Learner Credential Wallet accounts**: viewing them,
searching them, deleting them, and resetting the DID that controls one. An
HTTP API of AWS Lambda functions behind a zcap-signature authorizer, deployed
with AWS SAM. The console that drives it is
[lcw-admin-front-end](https://github.com/digitalcredentials/lcw-admin-front-end).

This is deliberately a small, separate thing. It is not part of the wallet, it
is not a general back office, and it is not where credentials live.

## What it is not

The wallet is three repos - [lcw-front-end][fe], [lcw-back-end][be] and
[was-server-aws][was] - and this is a fourth that shares exactly one thing with
them: **the accounts table**. That table holds an email, the `did:key` that
controls the account, the URL of the account's Wallet Attached Storage space,
and a creation timestamp. Four fields. That is the whole of what can be
administered here.

Credentials are not in it. They live in the account's WAS space, which is a
separate system that this API holds **no permission of any kind over** - no S3
policy, not even read. An admin can revoke someone's access to their space. An
admin cannot open it, copy it, or destroy it.

[fe]: https://github.com/digitalcredentials/lcw-front-end
[be]: https://github.com/digitalcredentials/lcw-back-end
[was]: https://github.com/digitalcredentials/was-server-aws

## The shape of it

| Method | Path | What it does |
| --- | --- | --- |
| POST | `/login` | Reports which admin the caller proved they are |
| GET | `/accounts` | One page of accounts; `?q=` filters, `?cursor=` continues |
| GET | `/accounts/{email}` | One account, with everything admins have done to it |
| DELETE | `/accounts/{email}` | Removes the account row, recording it first |
| PUT | `/accounts/{email}/did` | Replaces the controlling DID |
| GET | `/audit` | Recorded admin actions, newest first |

Three tables are involved. `wallet-test` (the accounts) is **owned by the
lcw-back-end stack**; this stack references it by name through the
`AccountTableName` parameter and never declares it, because two stacks
declaring one table would contend over it. `lcw-admin` and `lcw-admin-audit`
are declared here.

## How authorization works

Every request - `/login` included - is an individually signed zcap invocation,
verified by one Lambda authorizer before any handler runs. There is no session,
no token, no cookie: nothing is issued at login that could later be stolen or
replayed, and there is no server-side session state to compromise. A signature
authorizes one request, which is why the authorizer's result cache is disabled
(`ReauthorizeEvery: 0`).

The caller's identity comes from the `keyId` in their own signature, never from
anything they assert in a body or header. That DID is looked up in the admin
table, and verification then proves they hold its private key. The two failure
modes therefore are: not registered, or cannot sign. Both come back as a bare
403.

**Admins are their own table.** An admin is not a wallet account with a flag
set - `wallet-test` has no column this API consults for privilege - so no
wallet account can be escalated into an admin, by this API or by anything that
writes to that table.

**There is no way to become an admin through this API.** Membership is granted
out of band with [`scripts/add-admin.mjs`](scripts/add-admin.mjs), by whoever
operates the deployment. An admin API that can grow its own membership is a
different and much larger thing than this one.

**There is no way to create a wallet account through this API either.**
Registration stays user-initiated, through the email confirmation flow in
lcw-back-end.

## Every action is recorded

`lcw-admin-audit` is append-only: no function in this stack is granted
`UpdateItem` or `DeleteItem` on it. Each record names the admin who acted
(DID and email), what they did, to whom, and when.

The record is written **before** the account is touched, and it carries enough
to undo the action:

- a deletion stores the entire row that was removed, so putting it back
  restores the account and its access to its space, intact
- a DID reset stores the previous DID, so the handover can be reversed

Two consequences follow, both intended. A failure to record aborts the action
rather than performing it unrecorded. And an action that is recorded but then
fails leaves a record of something that did not happen - the API says so in its
response, and the row itself is the evidence.

## Resetting a controlling DID is a handover

Whoever holds the new key controls the account and everything in its space,
immediately and silently: `lcw-login` reads the DID from this row, and the WAS
authorizer resolves the space's controller through this same row. It is the
strongest thing an admin can do here.

So the API takes a `did:key` and validates it strictly - an Ed25519
`did:key:z6Mk...` and nothing else. A typo would hand the account to a key
nobody holds, and neither its owner nor an admin could ever sign for it again.

The privacy-respecting flow is that the **account holder generates their own
key and hands over only the public DID**, so their passphrase never leaves
their machine. The wallet has no screen that shows someone their DID yet, which
is the gap that makes the alternative - an admin choosing a passphrase and
reading it out - necessary for now. That alternative means an admin briefly
holds a credential that opens someone's wallet, and the console says so plainly
where it offers it.

One known loose end: the space's own `metadata/description.json` records a
`controller`, seeded at registration. The WAS authorizer does not consult it -
it reads this table - so a reset takes effect immediately, but
`GET /space/{id}` will still report the old controller. Correcting it would
require write access to the space, which this API deliberately does not have.

## Running it locally

The local stack lives in [lcw-front-end][fe] - see its `AGENTS.md` - and
substitutes DynamoDB Local for the real table, so nothing here needs AWS
credentials. Bring that up first, then:

```bash
npm install                      # scripts and tests
npm --prefix src/authorizer install
sam build

# register yourself as an admin (creates the local tables if missing)
node scripts/add-admin.mjs --endpoint-url http://localhost:8000 \
  --email you@example.org --passphrase 'a long passphrase'

# the admin API, on :3002
sam local start-api --port 3002 --region us-east-1 \
  --docker-network lcw-local \
  --parameter-overrides DynamoEndpointUrl=http://lcw-dynamodb:8000 \
  --warm-containers EAGER
```

`--passphrase` derives the DID exactly as the wallet does
(`SHA-256(passphrase)` as the Ed25519 seed). Prefer `--did` outside local
development, so the passphrase never leaves the admin's machine.

Then exercise the whole API end to end:

```bash
node scripts/smoke.mjs --passphrase 'a long passphrase'
```

It seeds a throwaway account of its own, re-keys it, deletes it, and checks
that both actions were recorded. It never touches accounts it did not create,
so it is safe to run alongside the wallet's local stack.

## Tests

```bash
npm test        # authorizer, in-process, against real signed invocations
```

These are the tests that matter most here: they sign genuine invocations and
assert that a non-admin is refused, that a signature cannot be replayed against
another route or another method, and that claiming a registered admin's `keyId`
without their key does not work.

## Four things that will bite you

**1. `sam local` decodes the request path; API Gateway does not.** The
signature covers the request target byte for byte, so an email encoded as
`smoke-test%40example.org` verifies when deployed and fails locally. Leave `@`
and `+` unencoded in the path - both are legal there - and the two agree. See
`pathSegment` in `scripts/smoke.mjs`.

**2. The query string is part of the signed target.** The authorizer
reassembles it from `rawQueryString`, which `sam local` does not provide, and
falls back to rebuilding it from `queryStringParameters`.

**3. `AWS_ENDPOINT_URL_DYNAMODB` cannot come from a template parameter.**
`sam local` renders an unset parameter as an empty string rather than omitting
the variable, and an empty endpoint is not something the SDK ignores. Hence
`DYNAMO_ENDPOINT_URL`, which each function reads itself and applies only when
non-empty - the same shape as `AWS_ENDPOINT_URL_S3` in was-server-aws.

**4. The authorizer bundle needs a `createRequire` banner.** `undici`, pulled
in transitively by the document loader, `require()`s node builtins from inside
a CJS module, and esbuild's ESM output has no `require`. Without the banner in
`template.yaml` the function dies on cold start with *"Dynamic require of
node:assert is not supported"*. (was-server-aws has the same exposure and has
so far only been saved by an older resolved `undici`.)

## Deploying

Not yet done, and not to be done casually: the accounts table is shared with a
live sandbox. `AccountTableName` must point at the right table for the
environment, and the first admin has to be registered with `add-admin.mjs`
against the deployed `lcw-admin` table before the console can be used at all.
