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
| GET | `/audit` | Recorded admin actions, newest first; `?limit=` and `?cursor=` page |

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

**The host is pinned, always.** The signed request target is built from the
caller's own `Host` header, so on its own the host check compares that header to
itself and binds a signature to nothing in particular. `ExpectedHost` fixes it
to this deployment, so an invocation made against a staging API cannot be
replayed against a production one.

It has **no default**, deliberately: an empty value disables the check, and a
parameter that can be omitted is one that eventually will be - a deploy
accepting defaults would ship with the pinning silently off. Locally, pass
`ExpectedHost=localhost:3002`; it must match the host the console actually calls,
letter case aside.

**A request body is authenticated in two places, and needs both.** An HTTP API
authorizer event carries headers but no body, so verifying the signature proves
the signed `Digest` header is genuine while proving nothing about the bytes that
actually arrived; the handler therefore re-checks the body against that digest
and refuses a mismatch.

That is only worth anything if the digest was signed, and by default it is not
always required to be. `@interop/http-signature-zcap-verify` adds `digest` to
the headers a signature must cover **only when the request carries a
`Content-Type`** - and the caller chooses whether to send one. So the authorizer
requires `digest` explicitly for every body-carrying method (`POST`, `PUT`,
`PATCH`). Without that, a signature made over a bodyless request to the same
target could be replayed with any body and a matching attacker-computed digest:
the handler's comparison would succeed against the attacker's own number, and
the account would be handed over, recorded against the admin who signed.

Both halves are tested - the authorizer refuses a body-carrying signature that
does not cover a digest, and `scripts/smoke.mjs` runs the full swap and strip
attacks against the running API.

## Every action is recorded

`lcw-admin-audit` is append-only to this API. Every function that writes to it
is granted `dynamodb:PutItem` on that table and nothing else, and each write is
conditional on its key not already existing, so a record can neither be altered
nor silently overwritten through the API. (`DynamoDBWritePolicy` would have
granted `UpdateItem` as well, which is why the policies here are written out
longhand. `sam validate` will not tell you that; expanding the template with
`samtranslator` and reading the roles will.)

What that does **not** cover: whoever holds AWS credentials for the table can
edit or delete rows directly, and `scripts/add-admin.mjs` writes to it as that
principal. The guarantee is against the API being turned against its own log,
not against the account that owns the table.

Every writer goes through one recorder ([`src/shared/audit.mjs`](src/shared/audit.mjs)),
so the `log` partition value the global feed depends on exists in a single
place. A writer that omitted it would keep working - the record would land, and
show under the account - while vanishing from `GET /audit`. The recorder is also
retry-safe: a `PutItem` whose response is lost is retried by the SDK, and that
retry fails its own condition, which taken for a collision would append a second
copy of one action to a log that cannot be corrected.

Each record names the admin who acted (DID and email), what they did, to whom,
and when. Nothing destructive proceeds without an identity to attribute it to:
if the authorizer context is missing, the handler refuses rather than writing an
anonymous record.

The record is written **before** the account is touched, and it carries enough
to undo the action:

- a deletion stores the entire row that was removed, so putting it back
  restores the account and its access to its space, intact
- a DID reset stores the previous DID, so the handover can be reversed

Two consequences follow, both intended. A failure to record aborts the action
rather than performing it unrecorded. And an action that is recorded but then
fails would leave a record of something that did not happen - so the handler
appends a second record saying so (`account.delete.aborted`,
`account.did.reset.aborted`). The log is only ever added to, so a correction is
another entry, never an edit.

The write itself is conditional on what was read: a DID reset only applies if
the account still holds the DID the record names as the previous one. A reset
racing another change returns 409 rather than overwriting a key the log does not
mention - which would have made the recorded undo restore the wrong one.

Granting and revoking admin rights is recorded too, by `add-admin.mjs`, marked
as unauthenticated because it is - that script is run by whoever holds AWS
credentials, and nothing about it is signed. Without those entries, an audit row
naming a DID could not be tied to a person once that admin was removed.

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
  --parameter-overrides DynamoEndpointUrl=http://lcw-dynamodb:8000 ExpectedHost=localhost:3002 \
  --warm-containers EAGER
```

The script refuses to register a DID that already belongs to another admin: two
admins sharing one key would make every action signed by it ambiguous, and the
authorizer refuses such a DID outright rather than attributing an action to
whichever row an index returned first. (The check reads a GSI, which cannot be
read consistently, so two registrations racing each other could still both land
- the authorizer then refuses that DID until one row is removed.)

Re-running it with the same DID does nothing and records nothing: the log is a
record of changes, not of invocations. A grant or revocation is recorded
**before** it is applied, as in the API, and a missing audit table aborts the
change rather than proceeding unrecorded.

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
live sandbox.

- `AccountTableName` defaults to `wallet-test`. That default is the test table,
  and it is the wrong one to administer by accident - set it explicitly.
- `ExpectedHost` has no default and must be the host the console will call. The
  stack creates only an `execute-api` host, whose name is not known until it
  exists, so a first deploy needs either a custom domain decided up front or a
  second deploy once `AdminApiUrl` is known.
- Register the first admin with `add-admin.mjs` against the deployed
  `lcw-admin` table; the console cannot be used at all until one exists.
- Neither table sets `DeletionPolicy: Retain` or point-in-time recovery. Before
  this is used for anything that matters, it should: `TableName` is a
  replacement-triggering property, so renaming a table parameter would delete
  the audit log rather than rename it.
- `recent-index` is sparse on the `log` attribute, which every record written by
  this code carries. If a deployment ever predates that attribute, its older
  records will be missing from `GET /audit` (though still visible under the
  account) until they are backfilled.
