# crAPI MCP Server — remote deployment + Claude Desktop

Runs the MCP server over **Streamable HTTP** and connects Claude Desktop to it
via a local `mcp-remote` bridge over an SSH tunnel — nothing is exposed to the
public internet.

Typical layout (two boxes):

```
Claude Desktop ─stdio─> mcp-remote (your Mac) ─HTTP/SSH tunnel─> MCP box :8009 ─HTTP─> crAPI box :8888
                                                                 192.168.1.102        192.168.1.101
```

Single-box works too — just point `CRAPI_BASE` at wherever crAPI listens and
tunnel to that same box. Port **8009** is used (not 8000) to avoid colliding
with common services.

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

---

## 6. Connect Claude Desktop (macOS)

Claude Desktop's built-in "Custom Connectors" connect **from Anthropic's cloud**,
which would require exposing this box to the public internet — not what you want
for a vuln-lab attack proxy. Instead, bridge locally with `mcp-remote` (needs
Node.js on your Mac: `node --version`, else `brew install node`).

### SSH tunnel (encrypted, nothing exposed)

Point the tunnel at the MCP box (use .102 if that's where the MCP server runs):

```bash
ssh -N -L 8009:localhost:8009 mcropsey@192.168.1.102
```

It goes silent after you authenticate — that blank terminal IS the tunnel.
Leave it open. Verify from a second tab:

```bash
curl -s http://localhost:8009/healthz          # -> ok
```

### Claude Desktop config

`~/Library/Application Support/Claude/claude_desktop_config.json` — add the
`crapi` block (keep any other settings/servers already in the file):

```json
{
  "mcpServers": {
    "crapi": {
      "command": "/opt/homebrew/bin/npx",
      "args": ["-y", "mcp-remote", "http://localhost:8009/mcp"]
    }
  }
}
```

Use the **full path** to npx (find it with `which npx`) — Claude Desktop launches
with a minimal PATH and usually can't find a bare `npx`. Add
`"--header", "Authorization: Bearer YOUR_TOKEN"` to args if you set MCP_AUTH_TOKEN.

Save → **Cmd+Q** Claude Desktop (full quit) → reopen → wait ~15s → ask
"what crapi tools do you have?"

---

## Notes

- The original file had a hardcoded crAPI JWT. It's now read from `CRAPI_TOKEN`
  (env) and normally unused — just `login`. Don't commit tokens to git.
- Single worker is intentional: the live crAPI session token lives in process
  memory, so multiple workers wouldn't share it.
- Logs: `journalctl -u crapi-mcp -f` (server), `~/Library/Logs/Claude/mcp-server-crapi.log` (Mac client).
- Changed SSH host key warning after a box rebuild is expected — clear it with
  `ssh-keygen -R <ip>` and reconnect.
