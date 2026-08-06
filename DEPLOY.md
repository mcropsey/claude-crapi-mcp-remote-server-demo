# crAPI MCP Server — remote deployment + Claude Desktop

Runs the MCP server over **Streamable HTTP** and connects Claude Desktop to it
via a local `mcp-remote` bridge that talks **directly to the MCP box over the
LAN** — no SSH tunnel. Nothing is exposed to the public internet; the traffic
stays on your private network.

Typical layout (two boxes):

```
Claude Desktop ─stdio─> mcp-remote (your Mac) ─HTTP (LAN)─> MCP box :8009 ─HTTP─> crAPI box :8888
                                                            192.168.1.102        192.168.1.101
```

Single-box works too — just point `CRAPI_BASE` at wherever crAPI listens and
point Claude at that same box's IP. Port **8009** is used (not 8000) to avoid
colliding with common services.

> **Why direct, not an SSH tunnel?** An earlier version of this guide used
> `ssh -L 8009:localhost:8009`. That works for reaching the server, but it has a
> side effect: the tunnel terminates on the MCP box and re-originates the request
> to `127.0.0.1:8009`, so the cleartext MCP traffic only ever exists on the box's
> **loopback** interface. The encrypted leg on the wire is just SSH on port 22.
> A network/API sensor (e.g. Noname) watching the LAN interface therefore never
> sees any `/mcp` traffic to classify. Connecting **directly** to the box's IP
> puts the `POST /mcp` requests on the real interface in cleartext, where a
> sensor can see and classify them. If you don't run a sensor and just want
> confidentiality, you *can* still tunnel — see the note at the end — but the
> default below is the direct path.

---

## 1. Put the files on the MCP box

Copy `server.py`, `requirements.txt`, `crapi-mcp.env`, `crapi-mcp.service` to the
box (scp from your Mac, or from another host). Then:

```bash
sudo useradd --system --home /opt/crapi-mcp --shell /sbin/nologin crapimcp
sudo mkdir -p /opt/crapi-mcp
sudo cp server.py requirements.txt crapi-mcp.env /opt/crapi-mcp/
```

## 2. Python venv + dependencies

RHEL/Rocky 9/10 ship a modern Python. Use 3.11+:

```bash
sudo dnf install -y python3.11
cd /opt/crapi-mcp
sudo python3.11 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt
sudo chown -R crapimcp:crapimcp /opt/crapi-mcp
```

## 3. Configure

Edit `/opt/crapi-mcp/crapi-mcp.env`:

- `CRAPI_BASE` — where crAPI is reachable **from this box** (default
  `http://192.168.1.101:8888`).
- `MCP_PORT` — defaults to `8009`.
- `MCP_AUTH_TOKEN` — optional but recommended. Generate with
  `openssl rand -hex 24`; forces clients to send `Authorization: Bearer <value>`.

If crAPI is on a different box, confirm this box can reach it:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://192.168.1.101:8888
```

Any HTTP code (200/302/404...) = reachable. A hang or `000` = firewall between
the boxes is blocking it.

You no longer paste a crAPI token into the code — call the `login` tool from
Claude and the server keeps the session token in memory.

## 4. Open the port (firewalld)

```bash
sudo firewall-cmd --add-port=8009/tcp --permanent
sudo firewall-cmd --reload
```

SELinux note: a plain systemd Python service runs unconfined on the default
targeted policy, so binding 8009 works out of the box. If you ever run it under
a confined domain and binding fails:
`sudo semanage port -a -t http_port_t -p tcp 8009`.

## 5. Install and start the service

```bash
sudo cp crapi-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now crapi-mcp
systemctl status crapi-mcp        # expect: active (running)
```

Smoke-test on the box:

```bash
curl -s http://127.0.0.1:8009/healthz          # -> ok
curl -s -X POST http://127.0.0.1:8009/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}'
```

A reply containing `"serverInfo":{"name":"crapi"...}` means it works. If you set
MCP_AUTH_TOKEN, add `-H "Authorization: Bearer YOUR_TOKEN"`.

Then confirm the box is reachable **from your Mac** over the LAN (this is the
path Claude will use — not loopback):

```bash
curl -s http://192.168.1.102:8009/healthz       # -> ok
```

If that hangs or refuses, open the firewall on the MCP box (section 4) — the
old SSH-tunnel setup sidestepped the firewall, so a direct connection may be the
first thing that actually exercises the inbound rule.

---

## 6. Connect Claude Desktop (macOS)

Claude Desktop's built-in "Custom Connectors" connect **from Anthropic's cloud**,
which would require exposing this box to the public internet — not what you want
for a vuln-lab attack proxy. Instead, bridge locally with `mcp-remote` (needs
Node.js on your Mac: `node --version`, else `brew install node`), pointed
directly at the MCP box's LAN IP.

### Claude Desktop config

`~/Library/Application Support/Claude/claude_desktop_config.json` — add the
`crapi` block (keep any other settings/servers already in the file):

```json
{
  "mcpServers": {
    "crapi": {
      "command": "/opt/homebrew/bin/npx",
      "args": ["-y", "mcp-remote", "http://192.168.1.102:8009/mcp", "--allow-http"]
    }
  }
}
```

Three things that matter here:

- **Use the box's IP, not `localhost`.** `http://192.168.1.102:8009/mcp` sends the
  request across the LAN to the real interface. (Pointing at `localhost` only
  works if you're tunnelling, which puts the traffic back on loopback.)
- **`--allow-http` is required.** `mcp-remote` refuses a plain `http://` URL to any
  non-localhost host unless you pass this flag — without it you get
  `Error: Non-HTTPS URLs are only allowed for localhost or when --allow-http flag is provided`
  and Claude shows "Server disconnected." This is the single most common reason
  the direct setup appears to fail.
- **Use the full path to npx** (find it with `which npx`) — Claude Desktop launches
  with a minimal PATH and usually can't find a bare `npx`. Add
  `"--header", "Authorization: Bearer YOUR_TOKEN"` to args if you set MCP_AUTH_TOKEN.

> **Security note:** `--allow-http` means the MCP traffic crosses your LAN in
> cleartext. That's exactly what lets a sensor read and classify it — but it also
> means anyone on that segment can read and drive these deliberately-vulnerable
> crAPI tools. Set `MCP_AUTH_TOKEN` (section 3) and add the `Authorization` header
> above so only you can invoke them; the payload stays cleartext (still visible to
> the sensor) but is gated by the token.

Save → **Cmd+Q** Claude Desktop (full quit, not just close the window) → reopen →
wait ~15s → ask "what crapi tools do you have?"

### Verify it's actually on the wire (not loopback)

The whole point of the direct setup is that the MCP traffic rides the LAN
interface. Confirm it after Claude reconnects — on the **MCP box**, while a tool
is running:

```bash
# the session's peer should be your Mac's IP, NOT 127.0.0.1
sudo ss -tnp | grep 8009
```

You want to see a peer of `192.168.1.188` (your Mac) on the `python` socket. If
you see `127.0.0.1`, an SSH tunnel is still in the path — kill it on the Mac with
`pkill -f 'ssh.*-L.*8009'` and make sure the config points at the IP, not
localhost.

To see the actual request on the wire:

```bash
sudo tcpdump -i eth0 -nn -A 'tcp port 8009'
```

Trigger a tool from Claude — you should see `POST /mcp` with `Host: 192.168.1.102:8009`
and a paired `200 OK`. That's the classifiable pair a sensor needs.

---

## Troubleshooting: MCP entry + tools appear, then disappear

### Root cause analysis (full history)

Three successive bugs were diagnosed and fixed:

**Bug 1 — GET /mcp → 405 (v1 stateless mode)**
The first build ran the transport in `stateless=True` mode. The MCP SDK rejects all
GET requests with 405 in stateless mode. `mcp-remote` sends a GET /mcp *before*
`initialize` to open the SSE stream, so every reconnect produced a bare GET→405 on
`/mcp` — a non-qualifying packet that untags the API under IC-75487.

Fix (v2): switched to `stateless=False` (stateful). The SDK then handles the
post-session GET as a live SSE stream (200). A new interceptor (`_presession_get_ok`)
was added to return 200 for the *pre-session* GET (the session-less one before
initialize). This fixed the 405 issue.

**Bug 2 — New random session ID on every `initialize` (v2 stateful mode)**
Stateful mode mints a fresh random `mcp-session-id` for each `initialize` call. With
`--loop` on the heartbeat/sweep, every 45-second cycle called `run_cycle()` which
started a new `initialize` and got a new random ID. Additionally the `_presession_get_ok`
handler was generating *another* random uuid4 per GET — different from the initialize
response's ID. Noname keyed its inventory on `mcp-session-id` and saw a different
"server" on every cycle, dropping and re-creating the tool inventory constantly.

The `MCP_SESSION_ID` env var was set in `crapi-mcp.env` but was never read by
`server.py` — comments marked it "inert". This was the central oversight.

**Bug 3 — `--loop` re-initialized every cycle (scripts)**
The `--loop` flag in both scripts called `run_cycle()` in a loop — but `run_cycle()`
did a full `initialize` at the start of every call. So `--loop` was not long-lived;
it was just short sessions at regular intervals. This amplified Bug 2 by producing a
new random session ID every 45–60 seconds.

### Current fix (v3 — all three bugs resolved)

`server.py`:
- `stateless=True` — no per-session state. Clients reconnect freely, no 404 "expired session".
- `_get_ok()` — intercepts **all** GET requests (pre- and post-session) and returns 200 with the pinned session ID. With `stateless=True` the SDK would 405 all GETs; this prevents that.
- `_wrap_send_inject_session_id()` — ASGI wrapper that injects `MCP_SESSION_ID` (from `crapi-mcp.env`) into **every** POST response header. Every client (heartbeat, sweep, Claude Desktop) always receives the same stable `mcp-session-id` regardless of how many times they reconnect or the service restarts.
- `MCP_SESSION_ID` is now read and used. If unset, a random id is minted once per process (stable for that run).

Scripts:
- `--loop` now calls `_run_loop()` which initializes **once** and reuses the session for all subsequent cycles. Re-initializes only when the server returns 404 (session expired). Confirmed: cycle 2+ shows `tools/list -> 200 cycle=N` with no new `initialize`.

### Verify the session ID is pinned

```bash
# Both calls should return the same mcp-session-id matching MCP_SESSION_ID in crapi-mcp.env
SID1=$(curl -sD - -o /dev/null -X POST http://127.0.0.1:8009/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' \
  | grep -i mcp-session-id)
echo $SID1
# Restart the service:
sudo systemctl restart crapi-mcp && sleep 2
# Run the curl again — must return the SAME id:
SID2=$(curl -sD - -o /dev/null -X POST http://127.0.0.1:8009/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' \
  | grep -i mcp-session-id)
echo $SID2
[ "$SID1" = "$SID2" ] && echo "PASS: session ID is stable" || echo "FAIL: IDs differ"
```

To intentionally create a fresh Inventory entry (e.g. after a lab rebuild), change
`MCP_SESSION_ID` in `crapi-mcp.env` to a new value and restart the service.

## Notes

- The original file had a hardcoded crAPI JWT. It's now read from `CRAPI_TOKEN`
  (env) and normally unused — just `login`. Don't commit tokens to git.
- Single worker is intentional: the live crAPI session token lives in process
  memory, so multiple workers wouldn't share it.
- Logs: `journalctl -u crapi-mcp -f` (server), `~/Library/Logs/Claude/mcp-server-crapi.log` (Mac client).
- The Mac client log line `Using MCP server command:` should read
  `npx ... mcp-remote http://192.168.1.102:8009/mcp` — if it shows anything else
  (e.g. a python path, or a `localhost` URL), Claude loaded a stale/duplicate
  config. Make sure there's exactly one `crapi` entry and fully quit/relaunch.

### Optional: SSH tunnel instead of direct (no sensor visibility)

If you have no API sensor and just want the hop encrypted, you can tunnel instead
of connecting directly:

```bash
ssh -N -L 8009:localhost:8009 mcropsey@192.168.1.102      # leave open
```

and point Claude at `http://localhost:8009/mcp` (drop `--allow-http`; localhost is
allowed). **Trade-off:** the cleartext MCP traffic then lives only on the MCP
box's loopback interface, so a network/API sensor watching the LAN interface will
**not** see it. Use the direct path (section 6) if you need the traffic visible to
a sensor. Don't do both at once — a leftover tunnel grabbing local 8009 will
silently override the direct config.

- Changed SSH host key warning after a box rebuild is expected (e.g. when you
  `ssh` in to administer the box) — clear it with `ssh-keygen -R <ip>` and
  reconnect.
