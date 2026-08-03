mcropsey  [10:37 PM]
Here is the low down:  Problem: Noname only tags an API as MCP when the response carries mcp-session-id or mcp-protocol-version and the request uses a recognized method (initialize/tools/list/tools/call). Your MCP server ran the streamable-HTTP transport in stateless mode, which suppresses the mcp-session-id header. So only the initialize handshake carried a marker; ongoing tools/call traffic didn't — the classification flapped and eventually aged your 28 MCP-Tool entries back to a single REST record.
The change (server.py, transport layer only — no tools touched):

Added a helper that re-emits both mcp-session-id and mcp-protocol-version on every/mcp response, injected at the ASGI layer.
Kept stateless=True (so restarts don't cause "Invalid or expired session ID" 404s) but strip any client-sent mcp-session-id before the manager sees it — that's what lets you have the header without the 404 risk.
Added a stable per-process session id + a default protocol version, both env-overridable (MCP_SESSION_ID, MCP_PROTOCOL_VERSION).
Deploy: copy server.py to /opt/crapi-mcp/, systemctl restart crapi-mcp. Verified end to end — headers on the wire (tcpdump) and in Noname's captured Samples.
One operational note that isn't a code fix: the classifier was sampling empty 202 notification responses instead of the 200 method calls, so it sat in learning as REST. Driving steady tools/list traffic through the learning window is what completes the flip back to MCP and repopulates the 28 tool entries.
In one line: the MCP session-id header was missing from most responses because the transport was stateless — we put both MCP markers back on every response while staying stateless, and fed the sensor qualifying tools/list traffic so it re-classifies.
Oz Smadja  [4:55 AM]
Hey, thanks for the analysis!
I dug into this and asked for product's sign-off to fix the behavior.

Today, when we receive a non-MCP packet to an MCP server (e.g. one missing the mcp-session-id header), we untag the server as MCP and delete all of its tools from the inventory - which is exactly what you hit.

Once we get an approval, we will change this: the MCP server tag will be sticky, and we'll stop deleting the MCP tools.