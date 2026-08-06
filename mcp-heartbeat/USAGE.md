# Keep the Noname MCP tag warm — and drive the whole crAPI API — without Claude

Two scripts, same MCP protocol plumbing, no Claude Desktop / `mcp-remote` needed:

- **`mcp_heartbeat.py`** — lightweight keep-alive. One short qualifying session
  (`initialize → notifications/initialized → tools/list → login + a few reads`).
  Use it purely to keep the **MCP tag** from going idle.
- **`crapi_sweep.py`** — full coverage. Calls **every** crAPI tool via
  `tools/call`, so the MCP server proxies to every real crAPI endpoint —
  reproducing a Claude-driven sweep from cron. Keeps the MCP tag warm AND
  generates full downstream crAPI API traffic (BOLA reads, writes, the works).

Pick the heartbeat if you just need the tag to stay up; pick the sweep if you also
want continuous traffic across the entire crAPI API surface.

Both scripts now open the **`GET /mcp` SSE stream** after `initialize`, exactly
like a real MCP client (`mcp-remote`) does — not just POSTs. That matters:
Noname's MCP fingerprint can key on seeing that Streamable-HTTP GET stream, so a
POST-only generator could be *seen but not classified as MCP*.

### Long-lived sessions (strongly recommended)

Noname currently keys Inventory identity on `mcp-session-id` and has non-sticky
tagging (IC-75487). Short-lived sessions (a new `initialize` every cron tick)
cause rapid create/drop of the MCP entry and its tools.

Both scripts support **`--loop`**, which performs `initialize` **once** and then
reuses the same `Mcp-Session-Id` for every subsequent `tools/list` + `tools/call`.
Re-handshake happens only if the server reports the session as expired.

> **Server-side pinning (v3 server):** `server.py` now injects a stable pinned
> `mcp-session-id` (from `MCP_SESSION_ID` in `crapi-mcp.env`) on **every** response,
> regardless of what the client sends. So even if the script re-initializes, the
> session ID Noname sees is always the same value. The `--loop` long-lived session
> behavior and server-side pinning are both active — belt and suspenders.

> **GET SSE stream (v3 server):** The server holds the GET /mcp SSE connection
> open with 30-second keepalive pings until the client disconnects. This matches
> what a real Streamable HTTP MCP client (`mcp-remote`) does and is what Noname's
> classifier keys on. Do **not** use a client that immediately closes the GET stream
> — that causes a retry storm (16+ GETs/sec) that looks anomalous to the classifier.

You can (and should) run **both** scripts at the same time:

```bash
# Heartbeat — lightweight keep-alive (long-lived session)
MCP_URL=http://192.168.1.102:8009/mcp python3 mcp_heartbeat.py --loop --interval 45

# Sweep — full coverage (read-only, long-lived session)
MCP_URL=http://192.168.1.102:8009/mcp python3 crapi_sweep.py --loop --interval 60 --mode reads
```

Prefer `tmux`/`screen` or the systemd units in **Option C** below. This is the
single biggest improvement for making the MCP tools stay visible in Noname.

### If the tag STILL doesn't appear when you run these (read this)

**Check in order:**

1. **Is 192.168.1.98 up?** `ping 192.168.1.98` from .102. If it's down, no traffic
   is being generated. Start .98 and wait 5–15 minutes.

2. **Is the session ID pinned?** On .102: `curl -sD - -o /dev/null -X POST
   http://127.0.0.1:8009/mcp -H "Content-Type: application/json" -H "Accept:
   application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":1,"method":
   "initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},
   "clientInfo":{"name":"t","version":"0"}}}' | grep -i mcp-session-id`
   Should return `dda4790c468c411384ab60193d50bed4`. If not, check `MCP_SESSION_ID`
   in `/opt/crapi-mcp/crapi-mcp.env`.

3. **Is there a GET flood?** `journalctl -u crapi-mcp -n 20 --no-pager` on .102.
   Should be mostly POSTs. If you see rapid GETs every fraction of a second, the
   SSE hold-open is broken — check the server version.

4. **Does the sensor see .98's traffic?** Close Claude Desktop, run only the
   heartbeat, and watch the `/mcp` record's *last-seen* in Noname.
   - **Last-seen updates** → sensor sees .98; scripts are working.
   - **Last-seen frozen** → sensor is blind to .98's path. Run scripts from the
     Mac (192.168.1.188) instead — that path is confirmed visible.

5. **MCP View vs API Inventory:** Per Noname, the MCP View requires `API Type = MCP`
   (set after the learning window), not just an MCP insight tag. Tags can lag first
   transaction by 5–15 minutes. Wait, then refresh.

Note: these scripts run anywhere Python + `requests` do, **including the Mac**
(`python3 mcp_heartbeat.py`), which is the known-good sensor path.

---

## mcp_heartbeat.py — keep the Noname MCP tag warm without Claude

Generates real qualifying MCP traffic (a full JSON-RPC session:
`initialize → notifications/initialized → tools/list → tools/call`) straight to
the crAPI MCP server. Run it on a schedule and the MCP tag stays continuously
re-learned — the same steady-traffic condition a production MCP server gets from
real clients. No Claude Desktop, no `mcp-remote` needed.

Run it **from a host other than the MCP box** (e.g. your Mac or a small utility
box) so the traffic crosses the LAN interface the sensor watches — not loopback.

## One-time setup (on whatever host will run it)

```bash
mkdir -p ~/mcp-heartbeat && cd ~/mcp-heartbeat
cp mcp_heartbeat.py .
python3 -m venv .venv
.venv/bin/pip install --upgrade pip requests
```

Test a single cycle (should print 200s and exit 0):

```bash
MCP_URL=http://192.168.1.102:8009/mcp .venv/bin/python mcp_heartbeat.py
```

## Option A — cron (what you asked for)

`crontab -e`, then add one line. Cron's finest granularity is 1 minute:

```cron
# every minute, quietly; only errors go to the log
* * * * * MCP_URL=http://192.168.1.102:8009/mcp /home/YOU/mcp-heartbeat/.venv/bin/python /home/YOU/mcp-heartbeat/mcp_heartbeat.py --quiet >> /home/YOU/mcp-heartbeat/heartbeat.log 2>&1
```

Every 2 minutes instead:

```cron
*/2 * * * * MCP_URL=http://192.168.1.102:8009/mcp /home/YOU/mcp-heartbeat/.venv/bin/python /home/YOU/mcp-heartbeat/mcp_heartbeat.py --quiet >> /home/YOU/mcp-heartbeat/heartbeat.log 2>&1
```

Use full absolute paths in cron (it has a minimal PATH and its own environment).
Put env vars inline on the command as shown, or load them another way — cron does
not read your shell profile.

### macOS note
Stock `cron` works on macOS but the process needs Full Disk Access in some setups.
If cron is flaky, use a launchd plist or just run `--loop` (Option B) in a
`tmux`/`screen` session.

## Option B — run forever with long-lived sessions (tmux / screen)

```bash
# Heartbeat (lightweight keep-alive)
tmux new -d -s mcp-hb \
  "MCP_URL=http://192.168.1.102:8009/mcp /usr/bin/python3 /home/mcropsey/mcp-heartbeat/mcp_heartbeat.py --loop --interval 45"

# Sweep (full coverage, read-only)
tmux new -d -s mcp-sweep \
  "MCP_URL=http://192.168.1.102:8009/mcp /usr/bin/python3 /home/mcropsey/mcp-heartbeat/crapi_sweep.py --loop --interval 60 --mode reads"
```

Each process holds its own long-lived `Mcp-Session-Id`. Run both if you want
light keep-alive traffic **plus** continuous coverage of every crAPI endpoint.

## Option C — systemd services (most robust, recommended)

Create **two** units so both scripts run with long-lived sessions.  
Do **not** redirect stdout/stderr to a file with `StandardOutput=append:...` — that commonly causes `Permission denied` (status 209/STDOUT). Let journald handle the logs.

`/etc/systemd/system/mcp-heartbeat.service`:
```ini
[Unit]
Description=MCP heartbeat (long-lived session for Noname)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mcropsey
Environment=MCP_URL=http://192.168.1.102:8009/mcp
ExecStart=/usr/bin/python3 /home/mcropsey/mcp-heartbeat/mcp_heartbeat.py --loop --interval 45
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/mcp-sweep.service`:
```ini
[Unit]
Description=MCP full sweep (long-lived session, reads)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mcropsey
Environment=MCP_URL=http://192.168.1.102:8009/mcp
ExecStart=/usr/bin/python3 /home/mcropsey/mcp-heartbeat/crapi_sweep.py --loop --interval 60 --mode reads
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-heartbeat mcp-sweep

# check status
systemctl status mcp-heartbeat mcp-sweep

# live logs (journald)
journalctl -u mcp-heartbeat -f
journalctl -u mcp-sweep -f
```

Both units use `--loop`, so each process holds one stable `Mcp-Session-Id` for its entire lifetime. This is the preferred way to keep the Noname MCP tag and tool list stable while also driving full API traffic.

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `MCP_URL` | `http://192.168.1.102:8009/mcp` | the MCP endpoint to hit |
| `CRAPI_EMAIL` | `mike1@my.lab` | account for the `login` tool call |
| `CRAPI_PASSWORD` | `Mylab123!` | password for `login` |
| `MCP_AUTH_TOKEN` | *(unset)* | only if the `/mcp` endpoint is bearer-gated |
| `MCP_PROTOCOL_VERSION` | `2025-06-18` | advertised protocol version |

## Why it's built this way

- **Each run is one complete session** — perfect for cron. It threads the real
  `Mcp-Session-Id` the server issues on `initialize` through every later request,
  exactly like a normal client, so every packet on `/mcp` is qualifying MCP traffic.
- **It does NOT send `DELETE /mcp`.** A session-terminating DELETE isn't a JSON-RPC
  method call, so under the not-sticky-tag behavior (Akamai IC-75487) it can read
  as a non-qualifying packet and untag the API. The script just lets the session
  lapse. (`--close` exists only if you want to test teardown on purpose.)
- **Tool-call errors are fine.** Even if a `tools/call` errors at the crAPI layer,
  it's still a valid MCP `tools/call` and counts as qualifying traffic — the tag
  only cares that the method is recognized and the response carries the markers.

## Verify it's landing on the wire the sensor sees (on the MCP box)

```bash
sudo tcpdump -i eth0 -nn 'tcp port 8009'
```

You should see `POST /mcp` from the heartbeat host paired with `200`s every cycle.
Then the MCP tag in Inventory should stop dropping between demos.

---

## crapi_sweep.py — drive EVERY crAPI endpoint via MCP, no Claude

> **Setup:** uses the same virtualenv as `mcp_heartbeat.py` — if you already did
> the "One-time setup" above (venv + `pip install requests`), there's nothing else
> to install; both scripts live in the same folder and share `.venv`. If you're
> starting here, do that setup section first.

This one calls every crAPI tool through `tools/call`, so the MCP server hits every
real crAPI endpoint. It harvests live ids each cycle (vehicle uuid, a post id, an
order id) so it keeps working across lab resets.

```bash
# one full sweep (all endpoints, including writes) then exit
MCP_URL=http://192.168.1.102:8009/mcp .venv/bin/python crapi_sweep.py

# safe read-only sweep — no data created, ideal for looping/cron
MCP_URL=http://192.168.1.102:8009/mcp .venv/bin/python crapi_sweep.py --mode reads

# run forever
MCP_URL=http://192.168.1.102:8009/mcp .venv/bin/python crapi_sweep.py --loop --interval 60 --mode reads

# bounded loop (e.g. 1000 cycles)
for i in $(seq 1000); do MCP_URL=http://192.168.1.102:8009/mcp .venv/bin/python crapi_sweep.py --mode reads --quiet; sleep 2; done
```

### Modes

| `--mode` | What it calls | Data side effects |
|---|---|---|
| `reads` | login + all GET/read endpoints + coupon check + the two BOLA reads (order 1, report 1) | none — idempotent, safe to loop forever |
| `all` (default) | everything: also `create_post`, `add_product`, `create_order`, `return_order`, `mechanic_signup`, `change_email`, `reset_password`, `verify_*`, `update_video_name`, `request_service`, `receive_report` | **creates lab data every cycle** (new posts/products/orders/mechanics) |

Use `--mode reads` for a continuous background loop/cron so you don't pile up
thousands of test posts and orders. Use the default `all` for a periodic full
exercise of the whole API (e.g. once every few minutes, or a bounded `--rounds`).

### Cron example (read-only, every 2 minutes)

```cron
*/2 * * * * MCP_URL=http://192.168.1.102:8009/mcp /home/YOU/mcp-heartbeat/.venv/bin/python /home/YOU/mcp-heartbeat/crapi_sweep.py --mode reads --quiet >> /home/YOU/mcp-heartbeat/sweep.log 2>&1
```

### Notes
- Like the heartbeat, it **never sends `DELETE /mcp`** (avoids the untag packet),
  and each cycle is a complete, self-contained MCP session.
- The four known tool/spec mismatches (`get_vehicle_details`, `get_all_users`,
  `request_service`, `receive_report`) and the two dummy-token 500s
  (`verify_email_token`, `verify_otp`) will show non-200s in `--mode all` — that's
  expected and still counts as qualifying MCP traffic.
