# Global JIT Policy Engine (Go + Postgres + GORM + CEL)

A production-ready, auditable authorization decision service for privileged sessions across various protocols and cloud platforms. Stores policies in Postgres, validates with CEL at write-time, evaluates with deterministic deny-overrides, and records audit traces and user-friendly reasons. Supports Unix/Linux, Windows RDP, web apps, network devices, storage, databases, thick clients, mail systems, hypervisor consoles, and cloud providers (AWS, Azure, GCP).

## What this service does
- CRUD APIs for policies in Postgres
- `/evaluate` API to return allow/deny for `{subject, resource, action, metadata}`
- Guarantees: write-time validation, deny-overrides with clear tie-breakers, cached CEL programs, audit trail, user-friendly reasons

## Project layout (key files)
- `cmd/migrate/main.go`: Run DB migrations (extensions, tables, indexes) via gormigrate
- `cmd/server/main.go`: Boot HTTP server; wires DB, eval engine, and routes
- `internal/model/policy.go`: GORM models: `Policy`, `PolicyAudit`
- `internal/model/hooks.go`: GORM hooks for `Policy` (CEL validation on create/update)
- `internal/policy/validate.go`: CEL compile/check used by hooks
- `internal/eval/engine.go`: Core evaluator: candidate fetch, sort, CEL eval, deny-overrides, caching, audit, reasons
- `internal/httpapi/handler.go`: `/evaluate` handler (returns decision, matched, reason, trace)
- `internal/httpapi/policies.go`: Policy CRUD handlers (`/policies`, `/policies/{id}`)

## Data model
- `Policy`
  - `id` uuid (default `gen_random_uuid()`), `name` string, `effect` `allow|deny`
  - `resource` pattern (e.g. `aws:s3:bucket/*`, `ssh:unix:host/*`, `cloud:aws:ec2/*`), `actions` text[] (empty = any)
  - `expr` CEL expression string; `metadata` jsonb (supports `message`, `non_match_message`)
  - `enabled` bool, `priority` int (lower wins), `version` int, timestamps
- `PolicyAudit`
  - `id` uuid, `request` jsonb, `decision` string, `matched_id` uuid|null, `trace` jsonb, `created_at`

## Evaluation algorithm (Two-Layer)
1) Evaluate global policies (provider="global") first:
   - Fetch enabled global policies prefiltered by action
   - In-memory resource match (glob), compute specificity
   - Sort by: priority asc → specificity desc → created_at asc → uuid asc
   - Evaluate CEL in order: true + deny ⇒ DENY immediately (deny-overrides)
   - If any global deny matches, return deny
2) If global policies pass, evaluate provider-specific policies:
   - Provider = req.cloud if not empty, else req.protocol
   - Fetch enabled provider policies prefiltered by action
   - In-memory resource match, sort, evaluate CEL
   - true + deny ⇒ DENY immediately; true + allow ⇒ remember allow
3) Result: allow if any allow and no deny; else deny (fail-closed on errors if configured)
4) Response includes `decision`, `matched`, `reason`, `trace`

## Getting started
Requirements: Go 1.22+, Postgres 14+

1) Start Postgres and DB
```bash
docker run --name jit-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:14
psql -h localhost -U postgres -c "CREATE DATABASE jitengine;"
```
2) Environment (PowerShell)
```powershell
$env:DATABASE_URL = "postgres://postgres:postgres@localhost:5432/jitengine?sslmode=disable"
$env:FAIL_CLOSED = "true"
```
3) Migrate
```powershell
go run ./cmd/migrate
```
4) Run server
```powershell
go run ./cmd/server
# listens on :8080 (override with ADDR)
```

## HTTP endpoints
- POST `/policies` — create policy (generic, use ?provider=aws|gcp|database|ssh|rdp|global)
- GET `/policies` — list policies (query: name/effect/enabled/provider)
- GET `/policies/{id}` — get policy
- PUT `/policies/{id}` — update policy (use ?provider=...)
- DELETE `/policies/{id}` — delete policy
- POST `/evaluate` — evaluate decision (two-layer: global policies first, then provider-specific)

### Example requests
Create policy
```bash
curl -i -X POST http://localhost:8080/policies -H "Content-Type: application/json" -d '{
  "name":"Allow analysts read",
  "effect":"allow",
  "resource":"aws:s3:bucket/bucket123/*",
  "actions":["s3:GetObject"],
  "expr":"subject.group == \"analyst\"",
  "metadata": {"message":"Read access granted for analysts."},
  "enabled":true,
  "priority":100
}'
```
Evaluate
```bash
curl -i -X POST http://localhost:8080/evaluate -H "Content-Type: application/json" -d '{
  "subject": {"group":"analyst"},
  "resource": "aws:s3:bucket/bucket123/file.txt",
  "action": "s3:GetObject",
  "metadata": {"now_hour": 10}
}'
```

## Writing policies (CEL)
- Variables: `subject`, `resource`, `action`, `metadata`, `protocol`, `platform`, `cloud`
- Examples: `subject.group == "analyst"`, `metadata.now_hour >= 9 && metadata.now_hour <= 18`, `protocol == "ssh" && platform == "unix"`, `cloud == "aws"`
- Validation: CEL is parsed/checked/compiled on create/update; invalid policies are rejected

### Global Resource Patterns
- SSH on Unix/Linux: `ssh:unix:host/*`
- RDP on Windows: `rdp:windows:host/*`
- Web applications: `web:http:app/*`
- Network devices: `network:router:device/*`, `network:switch:device/*`, `network:firewall:device/*`
- Storage: `storage:nas:volume/*`
- Databases: `db:oracle:instance/*`, `db:mssql:instance/*`
- Thick clients: `client:sap:gui/*`, `client:eclipse:ide/*`
- Mail systems: `mail:exchange:cloud/*`
- Hypervisor consoles: `hypervisor:console:vm/*`
- Cloud VMs: `cloud:aws:ec2/*`, `cloud:azure:vm/*`, `cloud:gcp:compute/*`

### Global Policy Examples
Create global deny policy (enforces compliance):
```bash
curl -i -X POST http://localhost:8080/policies?provider=global -H "Content-Type: application/json" -d '{
  "name":"Global Context Enforcement",
  "effect":"deny",
  "resource":"*",
  "actions":null,
  "expr":"!subject.device.compliant || subject.geo.country not in [\"IN\",\"US\",\"SG\"] || subject.justification.ticket_id == \"\" || subject.session.active_sessions > 0",
  "metadata": {"message":"Access denied due to global context violation."},
  "enabled":true,
  "priority":10
}'
```

Create SSH access policy for admins:
```bash
curl -i -X POST http://localhost:8080/policies?provider=ssh -H "Content-Type: application/json" -d '{
  "name":"Allow admins SSH",
  "effect":"allow",
  "resource":"ssh:unix:host/*",
  "actions":["connect"],
  "expr":"subject.role == \"admin\" && protocol == \"ssh\" && platform == \"unix\"",
  "metadata": {"message":"SSH access granted for admins."},
  "enabled":true,
  "priority":50
}'
```

Evaluate SSH session:
```bash
curl -i -X POST http://localhost:8080/evaluate -H "Content-Type: application/json" -d '{
  "subject": {"role":"admin", "device":{"compliant":true}, "geo":{"country":"US"}, "justification":{"ticket_id":"TICKET-123"}, "session":{"active_sessions":0}},
  "resource": "ssh:unix:host/example.com",
  "action": "connect",
  "protocol": "ssh",
  "platform": "unix",
  "metadata": {}
}'
```


 