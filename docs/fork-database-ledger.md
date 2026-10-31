# Fork database ledger

This is the maintained inventory of database changes owned by the NanoClaw /
BananaClaw fork of AgentVault. It separates the intended final storage model
from the historical steps used to reach it, so the fork delta can eventually be
consolidated into one reviewed change without retaining superseded machinery.

**This ledger does not authorize consolidation, deletion, a database reset, or
changes to deployed migration history.** Existing migrations and databases remain
unchanged. Never record credential values, tokens, encrypted payload contents,
or deployment-specific identities here.

Initial inventory: 2026-10-30. Include uncommitted changes when updating it.

## Baselines

| Reference | Pinned commit | Meaning |
|---|---|---|
| Original fork point | [`872578e4cdf9e03d5e3bcb5512023a70bf90ed65`](https://github.com/Infisical/agent-vault/commit/872578e4cdf9e03d5e3bcb5512023a70bf90ed65) | Parent of the first fork commit, `a29af13` (headless bootstrap, 2026-10-20). |
| Latest incorporated upstream checkpoint at initial inventory | [`d5836ec3bb2315de38043d742ae5daca11a4944a`](https://github.com/Infisical/agent-vault/commit/d5836ec3bb2315de38043d742ae5daca11a4944a) | Incorporated through merge `a2d567b` on 2026-10-22; also the merge base with the local `upstream/main` reference at capture. |

Keep the original fork point fixed. When upstream is incorporated again, record
the new checkpoint separately and classify upstream changes as upstream, not as
fork additions. Consolidation should target an explicitly chosen upstream
checkpoint, not a moving branch name.

Upstream already provides users, vaults, credentials, sessions, agents,
`vault_grants`, settings, broker configuration, encryption/key wrapping, the
SQLite/PostgreSQL backends, and migration tracking. Their existence is not a
fork schema addition. The modifications below are.

## Fork SQL migration lineage

Migration registration is distributed across packages, not just
`internal/store`. These are all fork SQL migrations identified at initial
inventory. FDB-005 was already deployed but uncommitted at initial inventory;
its introducing commit is now recorded below.

| ID | Migration / origin | Database change | Consolidation disposition |
|---|---|---|---|
| FDB-001 | [`20261021220000_mcp_oauth`](../internal/mcpauth/20261021220000_mcp_oauth.go), commit [`dd51e1d`](https://github.com/dtreskunov/agent-vault/commit/dd51e1d), 2026-10-21 | Adds encrypted `gateway_oauth_records` and index `gateway_oauth_record_lookup`. | Keep required current OAuth storage; do not retain superseded record layouts or group-owned headless account semantics merely because they used this table. |
| FDB-002 | [`20261022170000_credential_usage`](../internal/statickeys/20261022170000_credential_usage.go), commit [`6953e17`](https://github.com/dtreskunov/agent-vault/commit/6953e17), 2026-10-22 | Adds `gateway_credential_usage`, keyed by credential ID with `ON DELETE CASCADE`, and `last_used_at`. | Has current reader/writer call sites. Decide its role in the final supported API and backend-copy policy before retaining or removing it. |
| FDB-003 | [`20261027230000_token_authorities`](../internal/mcpauth/20261027230000_token_authorities.go), commit [`8c240e8`](https://github.com/dtreskunov/agent-vault/commit/8c240e8), 2026-10-27 | Adds `gateway_oauth_token_authorities(authority PRIMARY KEY)`. | Keep persistent token-authority interception/tombstone behavior. This is a security requirement, not just migration baggage. |
| FDB-004 | [`20261029190000_managed_connections`](../internal/store/20261029190000_managed_connections.go), commit [`fa89a2f`](https://github.com/dtreskunov/agent-vault/commit/fa89a2f), 2026-10-29 | Extends native users/vaults; adds connections, grants, audit, indexes, constraints and native-authorization triggers. | Keep the current user-owned, whole-credential model and native authority checks. Superseded service-selection snapshots are identified below. |
| FDB-005 | [`20261030192500_connection_wide_grants`](../internal/store/20261030192500_connection_wide_grants.go), commit [`89128b4`](https://github.com/dtreskunov/agent-vault/commit/89128b4), 2026-10-30; deployed locally 2026-10-30 | Replaces grant-authority checks and backfills non-revoked grant snapshots for whole-credential access. Adds/drops no columns. | A transition between two fork models. Eventually fold the final constraints into the consolidated definition and omit obsolete snapshots/backfill there. Do not delete the deployed migration or its history now. |

### OAuth record schema: FDB-001 and FDB-003

- `gateway_oauth_records`: `vault_id`, `kind`, `record_key`, `ciphertext`,
  `nonce`, `expires_at`, `account_key`; primary key
  `(vault_id, kind, record_key)`, vault foreign key with cascading deletion.
  The lookup index covers `(kind, record_key)`. SQLite uses BLOB and PostgreSQL
  uses BYTEA for encrypted bytes.
- SQL shape alone is not the whole contract: encrypted account, client, app and
  pending-flow payloads have evolved. Generic OAuth app configuration replaced
  the provider catalog in `8c240e8`; managed ownership, connection IDs and
  initiating-user binding arrived in `fa89a2f`.
- The current headless model requires library-owned OAuth state and explicit
  connection ownership. Earlier group-owned state is rejected by
  [model validation](../internal/mcpauth/validate.go), not automatically adopted.
- `gateway_oauth_token_authorities` must survive account/grant revocation so
  stale synthetic token handles cannot bypass interception after account removal.

### Native schema delta: FDB-004

| Upstream object | Fork-owned changes |
|---|---|
| `users` | Adds `auth_mode` (`local` / `managed`), `installation_id`, `subject`, `display_name`, and unique managed identity `(installation_id, subject)`. Allows absent human login material for managed users while requiring it for local users. Replaces global email uniqueness with the partial `users_local_email` index for local users. |
| `vaults` | Adds `purpose` (`group` / `system` / `library`), native `owner_user_id` foreign key, and unique per-owner library index `vaults_user_library`. Classifies `default` as `system`. |
| `sessions` | No fork columns added here; adds checks preventing managed human sessions and personal-library proxy sessions, including updates. |
| `vault_grants` | No fork columns added here; adds library-membership restrictions and native-admin-loss enforcement. |

SQLite temporarily rebuilds `users` through `users_managed`; that temporary
table is conversion machinery, not a final model entity. PostgreSQL alters the
existing columns and constraints. A future consolidation must express the same
final invariants on both backends, without keeping unnecessary intermediate
definitions.

Fork-owned tables introduced together:

- `connections`: stable ID, native owner and library foreign keys, label,
  kind/status, source `revision`, `services_json`, `keys_json`, resource/app
  identity, requested scopes, and deletion state.
  The 2026-10-31 credential-authentication update adds optional `auth.location`
  (`header` / `query`) and `auth.parameter` in `services_json`, not SQL columns
  or a migration. Missing location retains header behavior. Connection writes
  require one shared authentication recipe across destinations; existing
  substitution records, values, revisions and grants are not rewritten.
- `connection_grants`: connection/group identity, access state, creator and
  unique group-bound `binding_handle`, plus the superseded snapshot columns
  described below.
- `connection_audit`: creation time, transport/effective actor, connection,
  recipient vault, revision, action and outcome. Audit history is not disposable
  compatibility state.

The migration also owns the checks/triggers (and PostgreSQL trigger functions)
for immutable managed identity, library ownership/purpose and membership,
connection ownership/resource/app identity, native grant ownership, managed-user
disablement and native-admin revocation. Keep those guarantees when combining
definitions; do not confuse authorization enforcement with an obsolete
permission model.

### Superseded grant model: FDB-004 -> FDB-005

| Element | Original meaning | Current role / eventual target |
|---|---|---|
| `connection_grants.services_json` | Selected service names for one agent. | Retained snapshot only; no longer limits authorization. Omit from the eventual consolidated whole-credential grant schema. |
| `connection_grants.bound_services_json` | Approved routing/authentication recipe snapshot. | Retained snapshot only; runtime reads current connection rules. Omit from that consolidated grant schema. |
| `connection_grants.approved_revision` | Connection-policy revision approved for that grant. | No longer an authorization gate. Omit from that consolidated grant schema. |
| SQLite `connection_grant_authority` / `connection_grant_authority_update`; PostgreSQL `enforce_connection_grant()` | Required native authority, a ready connection and matching approved revision. | FDB-005 removes readiness/revision matching from grant persistence, preserving native owner/admin authority. Runtime still blocks unavailable credentials. Keep this final constraint behavior. |

**Do not remove `connections.services_json` or `connections.revision` on that
basis.** Current URL/authentication rules, conditional writes and in-flight
policy invalidation still depend on them.

The final grant relationship is whole-credential access to current and future
rules. Revoked and authority-paused grants must not be reactivated by a schema
cleanup. Preserve recipients, creator identities, binding handles and audit
references; no grant must still mean no credential access.

## Persisted contracts without dedicated SQL migrations

These are also fork database changes and belong in any future consolidation
review, even though their backing tables are upstream-owned.

| Contract | Origin / source | What must be accounted for |
|---|---|---|
| Bootstrap `nanoclaw-host` agent, native default-vault grant and transport session | `a29af13`; [headless bootstrap](../internal/headless/headless.go) | Reuses upstream agent/session/grant tables. Preserve explicit bootstrap/recovery semantics; this is not a new identity directory. |
| `vault_settings.unmatched_host_mode` | `d141569`; [CONNECT policy](../internal/blindtunnel/policy.go) | Per-vault `tunnel` / `mitm` / `deny` override in an existing settings table; absence uses the configured default. |
| `instance_settings["gateway.socket_sessions"]` | `ee49f78`; [socket persistence](../internal/socketsessions/persistence.go) | Encrypted versioned envelope containing socket root, bindings and session identity. Preserve validated restart/revocation behavior, not raw token values in documentation. |
| `instance_settings["gateway.oauth_app.<id>"]` and encrypted app records in library vaults | Generic apps in `8c240e8`, managed-library semantics in `fa89a2f`; [app storage](../internal/mcpauth/apps.go) | Install/private app scope, issuing-client binding, write-only secrets and current payload validation. Do not preserve old provider-catalog payloads as a fallback. |
| Credential rows for connection-owned static and OAuth material | `dd51e1d`, `8c240e8`, `fa89a2f`; [connection storage](../internal/server/connections.go), [OAuth repository](../internal/mcpauth/repository.go) | Existing credential columns gain fork usage: `mcp_oauth` / `oauth_app` types, connection-specific key names, encrypted OAuth material and generated routing references. IDs/key namespaces are on-disk contracts, not safe to rename casually. |

## Backend-transfer and deployment dependencies

- [Migration registration](../internal/store/migrate_gorm.go) derives names from
  source filenames. Already-applied names are deployment history; moving or
  deleting files is not by itself a safe consolidation procedure.
- [SQLite-to-PostgreSQL transfer](../internal/store/migrate.go) has fork changes
  for native user/vault fields, [connections/grants/audit](../internal/store/migrate_connections.go)
  and [OAuth records/authorities](../internal/store/migrate_gateway_oauth.go).
  Update these column lists against the final schema during consolidation.
  Backend transfer is a supported capability, not automatically obsolete merely
  because it contains the word "migration".
- At initial inventory, `gateway_credential_usage` has reader/writer call sites
  but is not in `MigrateData`'s copy steps. Record a preserve/reset decision for
  those usage timestamps before claiming complete backend-copy parity.
- FDB-005 was verified on a private copy and then applied locally on 2026-10-30.
  It rewrote 54 non-revoked snapshots without changing grant recipients, states,
  binding handles or connection lifecycle. This is historical deployment
  evidence, not proof that every other installation has the same state.
- This ledger covers AgentVault's database. NanoClaw's host database identity
  mapping/outbox is a separate schema and must be coordinated at cutover, not
  folded into this database by assumption.

## Keeping the ledger current

For every fork change affecting DDL, indexes, triggers, persisted JSON/encrypted
payloads, setting keys, bootstrap data, enums or data-copy logic:

1. Update the relevant entry, or add a new stable `FDB-*` entry. Record its
   introducing commit/migration, affected objects, purpose, backend behavior and
   dependencies. Land the commit reference when a working-tree entry is committed.
2. Explicitly classify final-model requirements versus transitional
   upgrade/backfill/compatibility work. Record removals and replacements rather
   than erasing their lineage.
3. Record deployment status separately from source history. Do not include
   secrets or infer that a committed migration ran everywhere.
4. Account for migration files outside `internal/store` and untracked files.
   At this checkpoint, these read-only commands reproduce the starting inventory:

   ```sh
   BASE=d5836ec3bb2315de38043d742ae5daca11a4944a
   git diff --name-status "$BASE" -- internal
   git log --reverse --format='%h %aI %s' "$BASE"..HEAD -- 'internal/**/2026*.go'
   git status --short --untracked-files=all -- internal
   git grep -n 'RegisterGORMMigration' -- internal
   ```

Before any eventual collapse, choose the intended upstream checkpoint and
whether existing installations need a separately approved one-time cutover.
Prove the final fresh schema and that cutover agree on SQLite and PostgreSQL,
including native authority, credential resolution, revocation, OAuth refresh,
socket restart, audit and data-copy invariants. Remove superseded fork steps
only as part of that approved change. Do not reset a live database, discard
audit/authority tombstones, rewrite Git history, or collapse upstream's own
migration history as an incidental cleanup.
