# crAPI MCP Lab — Diagnostic Findings & Fix Log

**Date:** August 2026  
**Environment:** MCP server at 192.168.1.102:8009, traffic gen at 192.168.1.98, sensor host (Mac) at 192.168.1.188  
**Symptom:** MCP traffic appears in Noname API Inventory then disappears; MCP View never populated

---

## Bug 1 — Session ID churn every 45–60 seconds

### Root cause
`server.py` ran with `stateless=False` (stateful mode). The MCP SDK mints a **fresh
random `mcp-session-id`** on every `initialize` call. Noname keys its Inventory entry
on `mcp-session-id`. Every new ID = a brand-new server = old tool inventory dropped.

Additionally, the env file had `MCP_SESSION_ID=dda4790c468c411384ab60193d50bed4`
pinned, but `server.py` never read that variable — a comment in the code literally
marked it *"inert."*

The `_presession_get_ok` function was generating a fresh `uuid.uuid4().hex` per GET
response — a **different** ID from the subsequent `initialize` response. So Noname
saw at least two distinct session IDs per reconnect cycle.

**Evidence:**
```
# Three consecutive initialize calls, all different:
Init 1: mcp-session-id: 679a029cf795477aa62ed568d153a2d4
Init 2: mcp-session-id: 8cbdb9f510ca4bd7a53fa13a499dff54
Init 3: mcp-session-id: 7f9e0c45e8754c7a91de84f1046ed8fc
# Pre-session GET returned yet another:
GET:    mcp-session-id: 4e50d347213949ee87485816dfbacb99
```

### Fix
Switched to `stateless=True`. Added `MCP_SESSION_ID` constant (reads from env,
falls back to one-time-per-process uuid). Added `_wrap_send_inject_session_id()`
ASGI wrapper that injects `mcp-session-id: dda4790c...` and `mcp-protocol-version`
on **every** POST response. Changed `_presession_get_ok` (later `_get_ok`) to use
the pinned constant instead of `uuid4`.

**Verification:**
```bash
# All three must return the same value matching crapi-mcp.env MCP_SESSION_ID
curl -sD - -o /dev/null -X POST http://127.0.0.1:8009/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' \
  | grep -i mcp-session-id
```

---

## Bug 2 — `--loop` mode re-initialized every cycle (not long-lived)

### Root cause
Both `mcp_heartbeat.py` and `crapi_sweep.py` `--loop` mode called `run_cycle()` in
a while loop. Each `run_cycle()` started a fresh `initialize`, which (under Bug 1)
got a new random session ID every 45s (heartbeat) or 60s (sweep).

The USAGE.md documented the *intended* behavior ("initialize once, reuse session"),
but the code never implemented it.

**Evidence from journald on .98 (before fix):**
```
20:42:04 initialize -> 200  session=b525777184ed4bbfb0d014369c3a29c3
20:42:49 initialize -> 200  session=d94dfb4cf175420b9b5eeaba09ec379e  ← new every 45s!
20:43:34 initialize -> 200  session=5f571ae126304caeb7dc72edc586d78b
```

### Fix
Added `_run_loop()` to `mcp_heartbeat.py` and `_run_loop()` + `_sweep_with_client()`
to `crapi_sweep.py`. `--loop` now calls `_run_loop()` which:
1. Initializes once
2. Reuses the session for all subsequent cycles
3. Re-initializes only when the server returns 404 (session expired)

**Verification:**
```
# After fix — cycle 2 has no initialize, just tools/list:
20:47:17 initialize -> 200  session=dda4790c468c411384ab60193d50bed4
20:47:18 cycle done: ok=4 errors=0 session=dda4790c468c411384ab60193d50bed4
20:48:03 tools/list -> 200  cycle=2       ← no initialize!
20:48:04 cycle done: ok=4 errors=0 session=dda4790c468c411384ab60193d50bed4
```

---

## Bug 3 — GET /mcp immediate-close caused retry storm

### Root cause
With `stateless=True`, the SDK returns 405 for all GETs. The `_get_ok` handler was
added to intercept GETs and return 200. But the first implementation closed the
stream immediately with `more_body=False` after sending `: ok\n\n`.

`mcp-remote` (Claude Desktop's bridge) maintains 4 concurrent SSE GET streams. When
an SSE stream closes, mcp-remote retries within ~250ms. With immediate-close + 4
connections:

```
16+ GET /mcp requests per second from 192.168.1.188
```

**Evidence from journald:**
```
20:57:54  GET /mcp 200 OK   (192.168.1.188:62595)
20:57:55  GET /mcp 200 OK   (192.168.1.188:62592)
20:57:55  GET /mcp 200 OK   (192.168.1.188:62593)
20:57:55  GET /mcp 200 OK   (192.168.1.188:62594)
20:57:55  GET /mcp 200 OK   (192.168.1.188:62595)
20:57:56  GET /mcp 200 OK   (192.168.1.188:62595)
... (continuous flood, ~16-20/second)
```

This flood looks nothing like real MCP traffic to Noname's classifier and likely
prevented `API Type = MCP` from being promoted in the MCP View.

### Fix
`_get_ok` now sends `: ok\n\n` with `more_body=True` (stream stays open), then
waits for `http.disconnect` with 30-second keepalive comments in between.

**Verification:**
```bash
# Should show 4 ESTAB connections from .188, not rapid connection/close cycling
ss -tnp | grep 8009
```
Expected output:
```
ESTAB  0  0  192.168.1.102:8009  192.168.1.188:6XXXX  (×4)
```

---

## Bug 4 — MCP View shows nothing / tools show with `-` host

### Root cause (per Noname SME Bot, Aug 2026)
Noname's **MCP View** requires `API Type = MCP` — not merely an MCP insight tag in
API Inventory. These are different:
- **Insight tag** = applied per-transaction when classification criteria are met;
  shows in the API Inventory tags column
- **API Type = MCP** = promoted after the learning window completes; required for
  the MCP View

Classification criteria (ALL must be true):
1. Transaction matches JSON-RPC criteria
2. Response includes `mcp-session-id` OR `mcp-protocol-version`
3. Request method is one of: `initialize`, `tools/list`, `tools/call`,
   `resources/list`, `resources/read`, `resources/templates/list`,
   `prompts/list`, `prompts/get`, `roots/list`, `sampling/createMessage`,
   `elicitation/create`, `ping`, `completion/complete`, `logging/setLevel`

The `-` host on tool entries in API Inventory = the tool entries exist but haven't
yet been fully associated with the server entity at `192.168.1.102:8009` (type
promotion pending).

The `crapi.cropseyit.com (46)` / `192.168.1.102:8009 (30)` grouping in the UI
confirms Noname DOES know about `:8009` and its 30 tools — the type just hasn't
been promoted yet.

**What prevented promotion:**
- Bug 1 (session ID churn): Noname couldn't form a stable learning record
- Bug 3 (GET flood): anomalous SSE pattern didn't match a real MCP client
- Learning lag: type promotion happens after the learning window, not on first transaction

### Fix
Bugs 1, 2, 3 resolved. After ~5–15 minutes of clean traffic (stable session ID +
proper long-lived SSE GETs + regular qualifying POSTs), `API Type = MCP` should be
promoted and the MCP View should populate.

**Known upstream issue:** IC-75487 (Noname). A single non-qualifying packet currently
untags an MCP server. IC-75487 will make the tag sticky with a grace period. Until
it ships, the session ID must remain pinned and all responses must be 200 with MCP
headers — any 4xx on `/mcp` will untag.

---

## Infrastructure finding — 192.168.1.98 VM shutdown

During diagnosis, 192.168.1.98 (traffic generator host) was powered off as a test.
Both `mcp-heartbeat` and `mcp-sweep` services stopped. Traffic from that host ceased.

**Key indicator in logs:** last POST from .98 at a specific timestamp; only bare
GETs from .188 after that. ARP entry for .98 showed `(incomplete)`.

**Lesson:** when traffic disappears from Noname, check .98 is up before debugging
code. `ping 192.168.1.98` from .102 is the fastest check.

---

## Summary of all changes made

| File | Change |
|---|---|
| `server.py` | `import asyncio` added |
| `server.py` | `MCP_SESSION_ID` constant added (reads from env, uuid4 fallback) |
| `server.py` | Config comment block rewritten to document v1/v2/v3 history |
| `server.py` | `stateless=False` → `stateless=True` |
| `server.py` | `_presession_get_ok` → `_get_ok`: uses pinned ID; holds stream open with keepalive |
| `server.py` | `_wrap_send_inject_session_id()` added: injects pinned ID on all POST responses |
| `server.py` | ASGI dispatcher: intercepts ALL GETs (not just session-less); wraps POST handler |
| `mcp_heartbeat.py` | `_run_loop()` added: truly long-lived session for `--loop` mode |
| `mcp_heartbeat.py` | `main()`: `--loop` calls `_run_loop()`; non-loop path unchanged |
| `crapi_sweep.py` | `_run_loop()` + `_sweep_with_client()` added: separates session from sweep logic |
| `crapi_sweep.py` | `main()`: `--loop` calls `_run_loop()`; non-loop path unchanged |
| `DEPLOY.md` | Troubleshooting section rewritten with full bug history and verification steps |
| `mcp discovery issue.md` | Rewritten as structured issue log with all 4 bugs documented |

---

## Operational runbook

### Service locations
| Service | Host | Command |
|---|---|---|
| crapi-mcp | 192.168.1.102 | `sudo systemctl restart crapi-mcp` |
| mcp-heartbeat | 192.168.1.98 | `sudo systemctl restart mcp-heartbeat` |
| mcp-sweep | 192.168.1.98 | `sudo systemctl restart mcp-sweep` |

### Quick health check
```bash
# On .102 — session ID stable and matches env file
curl -s -X POST http://127.0.0.1:8009/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' \
  -D - | grep -i mcp-session-id
# Expected: mcp-session-id: dda4790c468c411384ab60193d50bed4

# On .102 — 4 persistent SSE connections from .188, no flood
ss -tnp | grep 8009
# Expected: 4× ESTAB from 192.168.1.188

# On .98 — cycle=N incrementing without re-initialize
journalctl -u mcp-heartbeat -n 5 --no-pager
# Expected: tools/list -> 200  cycle=N (N > 1, no initialize between cycles)
```

### If MCP disappears from Noname again
1. Check .98 is up: `ping 192.168.1.98` from .102
2. Verify session ID is still pinned (curl above)
3. Check for GET flood: `journalctl -u crapi-mcp -n 20 --no-pager` — should be POSTs, not rapid GETs
4. Check services on .98: `ssh mcropsey@192.168.1.98 'systemctl status mcp-heartbeat mcp-sweep'`
5. If session ID changed, check if `MCP_SESSION_ID` is still set in `/opt/crapi-mcp/crapi-mcp.env`
6. Wait 5–15 minutes after restoring clean traffic for Noname's learning window

### To intentionally create a fresh Noname inventory entry
Change `MCP_SESSION_ID` in `/opt/crapi-mcp/crapi-mcp.env` to a new value:
```bash
openssl rand -hex 16
# paste result as MCP_SESSION_ID=<new-value>
sudo systemctl restart crapi-mcp
```
