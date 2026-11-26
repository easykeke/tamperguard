# TamperGuard HTTP API (v1, MVP)

Base path: `/api/v1`. Content type: `application/json` unless noted.
All responses use `{"error": "<code>", "message": "<human text>"}` on failure.

Two independent authentication schemes share one listener:

- **Admin (browser)**: `tg_session` HttpOnly cookie set by `POST /auth/login`.
  Mutating requests must send `Content-Type: application/json`.
- **Agent / publisher (machine)**: mutual TLS. The server verifies the client
  certificate against the TamperGuard CA and maps the certificate CN to an
  agent ID. No cookies, no bearer tokens.

## Common objects

### Capabilities
```json
{"bpf_lsm": true, "fanotify": true, "btf": true, "kernel_release": "6.6.87"}
```

### Node
```json
{
  "id": "n_7f3a...", "hostname": "web-01", "role": "protect",
  "status": "online", "enforcer": "ebpf-lsm",
  "policy_id": "pol_1", "policy_version": 3, "policy_digest": "ab12...",
  "degraded": false, "degraded_approved": false,
  "caps": {"bpf_lsm": true, "fanotify": true, "btf": true, "kernel_release": "6.8.0"},
  "agent_version": "0.2.1", "last_seen": 1732000000, "enrolled_at": 1731000000
}
```

### Policy
```json
{
  "id": "pol_1", "name": "webroot", "version": 3,
  "paths": [
    {"path": "/var/www/site", "recursive": true, "mode": "enforce"},
    {"path": "/var/www/site/cache", "recursive": true, "mode": "observe"}
  ],
  "writers": [
    {"kind": "publisher", "id": "pub_1"},
    {"kind": "process", "exe_path": "/usr/bin/rsync", "uid": 0}
  ],
  "updated_at": 1732000000
}
```

### Audit record
```json
{
  "seq": 42, "agent": "pub_1", "ts": 1732000000, "kind": "write.blocked",
  "decision": "deny", "path": "/var/www/site/shell.php", "op": "open_write",
  "subject": "exe:/bin/bash pid:8123", "token_id": "", "prev": "9c1f...",
  "hash": "aa2b...", "sig": "b7e0..."
}
```

## Public

| Method | Path | Body / Query | Notes |
|---|---|---|---|
| GET | `/healthz` | — | `{"status":"ok","version":"0.2.1"}` |
| POST | `/auth/login` | `{"username","password"}` | Sets cookie, returns `{"username","role"}` |
| POST | `/auth/logout` | — | Clears cookie |
| GET | `/auth/me` | — | 200 with user, 401 if absent |
| POST | `/agent/enroll` | `{"bootstrap_token","hostname","role","csr_pem","agent_version"}` | Returns `{"agent_id","cert_pem","ca_pem","server_time","config":{"issuer_public_key","policy_public_key"}}` |

`role` is `protect` or `publish`.

## Admin

### Overview
`GET /overview` →
```json
{"nodes_total": 4, "nodes_online": 3, "nodes_degraded": 1,
 "blocked_24h": 12, "tokens_active": 1, "chain_alerts": 0}
```

### Nodes
| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/nodes` | — | List of Node |
| GET | `/nodes/{id}` | — | Node + `recent_audit` (last 20 records) |
| POST | `/nodes/{id}/degraded-approval` | `{"approved": true}` | Admin explicitly accepts degraded protection |
| DELETE | `/nodes/{id}` | — | Revokes the node identity (certs rejected afterwards) |

### Policies
| Method | Path | Body |
|---|---|---|
| GET | `/policies` | — |
| POST | `/policies` | `{"name","paths","writers","assign_nodes":["n_1"]}` |
| GET | `/policies/{id}` | — |
| PUT | `/policies/{id}` | same as POST minus id; bumps `version`, agents re-sync |
| DELETE | `/policies/{id}` | — (409 if assigned to nodes) |

Policies are validated server-side and signed (Ed25519) before delivery;
agents reject a snapshot whose signature or digest is wrong.

### Publish flow
1. Admin creates a publish request (browser never sees a token).
2. The publisher agent picks it up, hashes its source tree, submits the manifest.
3. Server validates the manifest, issues a short-lived token bound to
   `node + publisher + paths + manifest digest`, returns it over mTLS.
4. Publisher writes files, re-hashing each one before the write, then reports completion.

| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/publish-requests?status=` | — | List |
| POST | `/publish-requests` | `{"node_id","publisher_id","source_dir","target_dir","delivery":"local\|pull","note"}` | `delivery` defaults to `local`; `pull` means the target node fetches the artefacts |
| GET | `/publish-requests/{id}` | — | Request detail |
| POST | `/publish-requests/{id}/cancel` | — | Only while `pending`/`manifest_received` |

Publisher-agent endpoints (mTLS, role=publish):

| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/publish/pending` | — | Requests assigned to the calling publisher |
| POST | `/publish/{id}/artifact` | raw body + `X-TG-SHA256` header, query `?path=<rel>` | Stages one file for pull delivery (must be uploaded before the manifest) |
| POST | `/publish/{id}/manifest` | `{"manifest":"sha256:...","files":[{"path","sha256","size"}]}` | → `{"token","expires_at","token_id","paths"}`; in pull mode every file must match a staged artefact |
| GET | `/publish/{id}/ready` | — | → `{"ready":bool,"token_id","node_id","status"}`: whether the target node has installed the grant |
| POST | `/publish/{id}/complete` | `{"ok":true,"error":""}` | Closes the request |

The publisher polls `/ready` until the node acknowledges the grant, then writes.
The polling is an optimisation: if it times out the publisher still attempts the
write and retries on `EPERM` while the token is valid.

### Tokens and revocations
| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/tokens` | — | Active + recent tokens |
| GET | `/revocations` | — | Revocation list (agents pull this) |
| POST | `/revocations` | `{"kind":"token\|subject\|node","value":"tok_...","reason":"..."}` | Immediate effect on next sync (≤30 s) |

### Audit
| Method | Path | Query | Notes |
|---|---|---|---|
| GET | `/audit` | `node_id,kind,limit,before_seq,from,to` | Newest first; `from`/`to` are unix seconds |
| GET | `/audit/export` | `node_id,kind,from,to,limit,format=jsonl\|csv` | Streaming evidence export; sets `Content-Disposition` |
| GET | `/audit/state` | — | Per-agent `{next_seq,last_hash,alert}` — gap/fork detection |
| GET | `/audit/verify` | `node_id` | Re-verifies the stored chain, returns `{ok, records, from_seq}`; verification starts at the oldest stored record, so a retention purge does not make it fail |

## Agent (mTLS)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/agent/heartbeat` | `{"status","enforcer","policy_digest","caps","degraded","audit_seq","enforcer_healthy"}` | Returns `{"policy":Snapshot,"grants":[...],"revocations":[...],"server_time","heartbeat_interval"}` |
| POST | `/agent/audit` | `{"records":[...]}` | Batch upload; server verifies chain, returns `{"ack_seq","alerts":[...]}` |
| POST | `/agent/grants` | `{"active_tokens":["tok_..."]}` | Agent reports which grants it actually installed; used by the publisher readiness check |
| GET | `/agent/manifest` | protect 角色 mTLS | 最近一次已完成 pull 发布的签名站点清单 `{node_id,request_id,manifest,target_dir,files[],signed_at,signature}`；无发布时 404 `no_release` |
| GET | `/agent/upgrade` | `current,os,arch` | `{"available","current","manifest":{"version","os","arch","sha256","size","signature"}}`; manifest is Ed25519-signed |
| GET | `/agent/upgrade/download` | `version,os,arch` | Streams the signed agent binary |
| GET | `/agent/stream` | — | `text/event-stream`. Events: `hello`, `policy`, `revoke`, `grant`. A dropped event only costs latency; the heartbeat reconciles. |

Agents heartbeat every 15 s and **also** hold a push stream. Policy changes,
revocations and new grants are pushed over the stream, so the worst-case
latency is the stream round trip (sub-second in practice); the heartbeat is the
fallback when the stream is down, which keeps the documented 30 s bound. The
stream sends a `: ping` comment every 20 s.

## Error codes

`unauthorized`, `forbidden`, `not_found`, `conflict`, `invalid`, `internal`,
`chain_broken`, `token_expired`, `revoked`, `degraded_not_approved`.
