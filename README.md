# sevshield

Scoped API-key proxy for sevDesk (many least-privilege sub-keys in, god keys stay server-side).

sevDesk issues one full-access token per user with no scopes and rotation only
via support. sevshield holds those god keys encrypted in SQLite or Postgres
and issues revocable sub-keys bound to one god key + a method + path
allowlist. Every proxied call is audit-logged.

```
client --(sub-key)--> sevshield --(god key)--> https://my.sevdesk.de/api/v1/*
```

## Quickstart (docker compose)

Prerequisites: Docker + Compose plugin.

```bash
cp .env.sample .env   # set ADMIN_TOKEN and KEY_ENCRYPTION_KEY (both required)
# generate fresh values with: openssl rand -hex 32
docker compose up --build -d
```

Data persists in the `sevshield-data` volume (`/data/sevshield.db`).

To use Postgres instead of SQLite:

```bash
cp .env.sample .env   # set ADMIN_TOKEN, KEY_ENCRYPTION_KEY and POSTGRES_PASSWORD
# uncomment DATABASE_URL in .env, then:
docker compose --profile pg up --build -d
```

Data then persists in the `pgdata` volume; `DATABASE_PATH` is ignored while
`DATABASE_URL` is set. The compose `db` service runs Postgres 18 — its volume
is not compatible with older major versions, so switching majors requires a
fresh volume (`docker compose --profile pg down -v` wipes it; back up first).
SQLite stays the default for `go run` (see below) —
set `DATABASE_URL` to point at any reachable Postgres to switch. Switching
backends starts with an empty database: existing rows are not migrated
automatically (re-add god keys and re-issue sub-keys).

Open `http://localhost:8080`, sign in with `ADMIN_TOKEN`, add a god key
(God keys tab), issue a sub-key (Sub-keys tab), use it:

```bash
curl localhost:8080/api/v1/CheckAccount -H "Authorization: sevsh_..."
```

## Quickstart (from source)

Prerequisites: Go 1.27+, Bun.

```bash
# 1. Build the UI first - it is embedded into the binary.
bun install --cwd web && bun run --cwd web build

# 2. Start the server (both env vars required). SQLite is the default;
#    export DATABASE_URL=postgres://... to use Postgres instead.
export ADMIN_TOKEN=$(openssl rand -hex 32)
export KEY_ENCRYPTION_KEY=$(openssl rand -hex 32)
go run ./cmd/sevshield
```

God keys are added via the UI (God keys tab) - each needs a name and its
sevDesk API token. The base URL is fixed to `https://my.sevdesk.de/api/v1`.

## Configuration

| Env | Required | Description |
| --- | --- | --- |
| `ADMIN_TOKEN` | yes | Bearer token for `/admin/*` + UI login |
| `KEY_ENCRYPTION_KEY` | yes | 64 hex chars; encrypts god keys at rest. The server refuses to start without it |
| `DATABASE_URL` | no | Postgres DSN (e.g. `postgres://user:pass@host:5432/db?sslmode=disable`). When set, Postgres is used and `DATABASE_PATH` is ignored |
| `DATABASE_PATH` | no | SQLite path, used only when `DATABASE_URL` is empty (default `./data/sevshield.db`) |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | pg compose only | Credentials for the `db` service with `docker compose --profile pg` |
| `PORT` | no | Listen port (default `8080`) |
| `DISABLE_UI` | no | `1` disables the built-in admin UI (`GET /` returns JSON; default `0` = UI enabled). Truthy values: `1`, `true`, `yes` (case-insensitive) |
| `IP_SOURCE_HEADER` | no | e.g. `X-Forwarded-For`; trusted client-IP source for allowlisting behind a reverse proxy. Only set this if the proxy strips/forwards it — otherwise clients can spoof their IP and bypass allowlists |
| `COOKIE_SECURE` | no | `1` sets the `Secure` flag on the admin session cookie (enable behind TLS, same truthy values as `DISABLE_UI`) |
| `PROXY_TIMEOUT_SECONDS` | no | Upstream request timeout for proxied `/api/v1/*` calls (default `30`) |
| `PROXY_MAX_BODY_MB` | no | Max buffered upstream response body in MB; larger bodies are truncated (default `20`) |

## API

Proxy (sub-key in `Authorization` header, raw or `Bearer`):

- `ALL /api/v1/*` - policy-checked forward to the bound god key's account
- `GET /healthz` - liveness probe (`{"ok": true}`)

Admin UI auth is an httpOnly session cookie (`POST /admin/login`,
`POST /admin/logout`, `GET /admin/me`; `SameSite=Strict`, 24h sliding
sessions kept server-side). API clients can keep using
`Authorization: Bearer $ADMIN_TOKEN`. Every admin call is audit-logged.

Admin API endpoints:

- `GET/POST /admin/keys`, `PUT /admin/keys/:id` (name, policy, IPs, expiry),
  `POST /admin/keys/:id/rotate` (fresh secret, returned once),
  `POST /admin/keys/:id/revoke`, `DELETE /admin/keys/:id`
- `GET/POST /admin/upstreams` (name + godKey; base URL fixed to
  `https://my.sevdesk.de/api/v1`), `PUT/DELETE /admin/upstreams/:id`,
  `POST /admin/upstreams/:id/test`
- `GET/POST /admin/notify`, `PUT/DELETE /admin/notify/:id`, `POST /admin/notify/:id/test`
- `GET /admin/stats` (dashboard counters: keys, upstreams, channels, audit totals + 24h denials/errors)
- `GET/POST /admin/policies` (policies can be created/overwritten, not deleted)
- `GET /admin/audit?limit=&offset=&source=&upstream=&keyPrefix=&status=` (default `limit=100`, max `500`; returns `{total, rows}`)
- `GET/PUT /admin/settings` (`{auditRetentionDays}`; `0` = unlimited, max `3650`)
- `POST /admin/audit/purge` (deletes rows older than the stored retention; optional `{retentionDays}` override for a one-off run)

Sub-keys support optional IP allowlists (IPs/CIDRs, empty = any) and expiry.

Notification channels (`webhook` with HMAC-signed JSON, `telegram` via Bot API,
`smtp` with STARTTLS/implicit TLS) fire on `denied` and `upstream_error` events
with a per-channel cooldown. Destructive actions (delete/revoke/rotate) ask for
a 6-digit confirmation code in the UI (UI-only safeguard, not server-enforced).

## Proxy limits

Proxied `/api/v1/*` calls forward method, query string and body to the bound
god key's account (`Content-Type` preserved, `Accept: application/json` set)
and return the upstream status/body verbatim. Two bounds apply:

- Upstream request timeout (`PROXY_TIMEOUT_SECONDS`, default `30`).
- Max buffered response body (`PROXY_MAX_BODY_MB`, default `20`); larger
  responses are truncated. Raise it for large sevDesk exports.

## Audit retention

Audit rows grow without bound unless you cap them. Set retention in the UI
(Audit logs tab → Retention, `0` = unlimited = default) or via
`PUT /admin/settings`. Saving applies immediately (old rows are deleted
synchronously), and the server re-enforces it on startup and once a day.
`POST /admin/audit/purge` runs a one-off purge without changing the setting.

## Operational notes

- Create a god key before issuing sub-keys (`POST /admin/keys` fails with
  “unknown upstream (create one first)” otherwise).
- Deleting a god key is blocked (`409 upstream still has sub-keys`) while
  sub-keys are bound to it — delete/re-bind those first.
- Rotating a sub-key returns the new secret once; the old value stops working
  immediately.
- Policies have no delete endpoint; seeded defaults (`sevdesk-sync`,
  `readonly`) are inserted once and never auto-updated — edit them via
  `POST /admin/policies` if the built-ins change.
- Disabling a god key makes its sub-keys return `503`, not `403`.

## Policies

Deny by default. A policy is `[{method, path}]` matched against the upstream
path (`Voucher/Factory/saveVoucher`); `*` = one segment, `**` = rest.
Seeded: `sevdesk-sync` (voucher + tag + invoice writes; reads for SevClient,
CheckAccount, Voucher, Invoice, Contact, CostCentre, TaxRule),
`readonly` (GET only). See `internal/policy`.

## Security notes

- God keys never leave the server (AES-256-GCM at rest, plaintext only in memory).
- Losing `KEY_ENCRYPTION_KEY` makes stored god keys unrecoverable; back it up separately from the DB.
- Changing `ADMIN_TOKEN` requires a restart; changing `KEY_ENCRYPTION_KEY` requires re-entering god keys.
- Allowed reads can still exfiltrate; keep policies minimal and rotate often.
- Run behind TLS (Caddy / Traefik / ingress), restrict `/admin/*` by network.
- Protect the database: the SQLite file (`DATABASE_PATH`, default
  `./data/sevshield.db`) via file permissions and backups, or the Postgres
  instance behind `DATABASE_URL` (network policy + managed backups).

## Layout

- `cmd/sevshield` - binary (Fiber, UI embedded)
- `internal/{config,crypto,db,model,policy,keys,proxy,admin,notify,session,retention}` - backend
- `internal/db` - backend selection: `DATABASE_URL` set = Postgres
  (`OpenPostgres`), otherwise SQLite (`OpenSQLite`); same `AutoMigrate`
  schema on both, no raw SQL
- `web` - SvelteKit (adapter-static) admin UI baked into the binary
