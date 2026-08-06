# MCP Discovery / Inventory Stability — Issue Log

## Noname response (original thread, Oz Smadja)

> Today, when we receive a non-MCP packet to an MCP server (e.g. one missing the
> mcp-session-id header), we untag the server as MCP and delete all of its tools
> from the inventory — which is exactly what you hit. Once we get approval, we will
> change this: the MCP server tag will be sticky, and we'll stop deleting the MCP tools.
>
> Tracked: IC-75487 (sticky tag), IC-72703 (display flap).

---

## Root cause iterations

### v1 — stateless mode + header injection (broke on GET→405)

Server ran `stateless=True`. Added a helper that re-emits `mcp-session-id` and
`mcp-protocol-version` on every `/mcp` POST response. But stateless mode rejects
**all** GET requests with 405. `mcp-remote` opens a GET /mcp SSE stream before
`initialize` on every connection. That GET→405 is a non-qualifying packet under
IC-75487, so the API was untagged on every Claude Desktop reconnect.

### v2 — stateful mode (broke on session ID churn)

Switched to `stateless=False`. The SDK now issues a real `Mcp-Session-Id` on
`initialize` and serves the SSE GET as a 200 live stream. Added `_presession_get_ok`
to handle the pre-session GET (before initialize) with a benign 200.

**New problem discovered (Aug 2026):** Stateful mode mints a NEW random
`mcp-session-id` for every `initialize` call. With `--loop` on the heartbeat/sweep,
each cycle called `run_cycle()` which started a new `initialize` — a new random ID
every 45 seconds. Noname sees each ID as a distinct server and drops/re-creates the
inventory constantly.

Also found: `MCP_SESSION_ID` in `crapi-mcp.env` was never read by `server.py` — a
comment marked it "inert". The `_presession_get_ok` function was generating a fresh
`uuid4` per GET, different from the `initialize` response's ID. Noname saw at least
two different session IDs per reconnect cycle.

Additionally: the `--loop` flag in both scripts was NOT maintaining a long-lived
session — it called `run_cycle()` in a loop, and each `run_cycle()` did a full
`initialize`. "Long-lived session" in `--loop` mode was never implemented; it was
short sessions at regular intervals.

### v3 — stateless + pinned ID + true long-lived sessions (current, Aug 2026)

**server.py changes:**
- `stateless=True` — no session validation. Clients reconnect freely without 404.
- `_get_ok()` — intercepts **all** GETs (not just pre-session) and returns 200 with
  the pinned `MCP_SESSION_ID`. Prevents the SDK's 405 from ever reaching the sensor.
- `_wrap_send_inject_session_id()` — ASGI wrapper on every POST response that injects
  the pinned `MCP_SESSION_ID` and `MCP_PROTOCOL_VERSION` headers. Every client always
  receives the same stable identifier.
- `MCP_SESSION_ID` is now read from `crapi-mcp.env`. If unset, a random ID is minted
  once per process (stable for the run, not across restarts — pin it in the env file).

**Script changes:**
- `--loop` now calls `_run_loop()` in both scripts, which initializes **once** and
  reuses the session. Re-initializes only on 404.
- Verified: cycle 2+ shows `tools/list -> 200 cycle=N` with no `initialize`. Session
  ID `dda4790c468c411384ab60193d50bed4` (pinned) remains constant across all cycles
  and across service restarts.

**Confirmed working:** both `mcp-heartbeat` and `mcp-sweep` services on .98 show the
pinned session ID in every cycle. The session ID is stable across server restarts on
.102 — the ASGI wrapper injects it from env regardless of what the SDK would return.

### v3 bug: GET flood from mcp-remote (fixed same session, Aug 2026)

The initial v3 implementation closed the SSE GET immediately with `: ok\n\n`
(`more_body=False`). mcp-remote treats a closed SSE stream as a drop and retries
within ~250ms. With 4 concurrent SSE connections from Claude Desktop, this produced
16+ GET /mcp → 200 pairs per second — a pattern that looks nothing like a real MCP
session to Noname's classifier.

Fix: `_get_ok` now sends the initial `: ok\n\n` with `more_body=True` and then waits
for `http.disconnect` (with 30-second keepalive comments). The 4 SSE connections from
mcp-remote stay `ESTAB` and are held open for the duration of the Claude session —
matching what real MCP traffic looks like on the wire.

**MCP View vs API Inventory (per Noname SME Bot):**
Noname's MCP View requires `API Type = MCP`, not merely an MCP insight tag. Tags in
Inventory are applied after the learning window and can lag the first transaction. The
GET flood was likely preventing the type from being promoted (anomalous SSE pattern).
With the fix, the traffic now matches a genuine Streamable HTTP MCP deployment:
- 4 persistent SSE GETs (long-lived, 30s keepalive)
- Regular POST tool calls with all required qualifying methods
- Stable pinned session ID on every response

---

## Key operational notes

- **IC-75487 not yet shipped.** Until Noname makes the MCP tag sticky, any
  non-qualifying packet (4xx without MCP context) can still untag the API. With v3
  this should never happen from these scripts — all responses are 200 with MCP markers.
- **Traffic must cross the sensor's tap.** The sensor watches a specific network
  interface. Traffic from .98 to .102 crosses the LAN and has been confirmed visible.
  Traffic from loopback (127.0.0.1 → 127.0.0.1) on .102 is NOT visible to a
  SPAN-based sensor — run scripts from .98 or the Mac (.188), not localhost on .102.
- **Do NOT send DELETE /mcp.** A session-terminating DELETE is not a JSON-RPC method
  call and can untag the API under IC-75487. Scripts never send DELETE unless `--close`
  is explicitly passed.
