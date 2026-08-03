#!/usr/bin/env python3
"""
mcp_heartbeat.py — keep Noname's MCP tag warm without Claude.

Speaks the MCP Streamable HTTP protocol directly to the crAPI MCP server, so it
generates the exact "qualifying" traffic the sensor needs to learn/retain the MCP
tag: a JSON-RPC session (initialize -> notifications/initialized -> tools/list ->
tools/call) whose responses carry mcp-session-id / mcp-protocol-version and use
recognized MCP methods.

Designed for cron: each invocation runs ONE complete session and exits. Point cron
at it every 1-2 minutes and the tag stays continuously re-learned — the same
condition a production MCP server gets naturally from constant client traffic.

It deliberately does NOT send DELETE /mcp at the end. A session-terminating DELETE
is not a JSON-RPC method call, so under the not-sticky-tag behavior (IC-75487) it
can read as a non-qualifying packet and untag the API. We just let the session
lapse. (Enable --close only if you specifically want to test teardown behavior.)

Usage:
    python3 mcp_heartbeat.py
    MCP_URL=http://192.168.1.102:8009/mcp python3 mcp_heartbeat.py
    python3 mcp_heartbeat.py --loop --interval 45      # run forever instead of cron
    python3 mcp_heartbeat.py --quiet                   # only print on error (good for cron)

Env:
    MCP_URL                 default http://192.168.1.102:8009/mcp
    CRAPI_EMAIL             default mike1@my.lab       (used for the login tool call)
    CRAPI_PASSWORD          default Mylab123!
    MCP_AUTH_TOKEN          set only if the /mcp endpoint is bearer-gated
    MCP_PROTOCOL_VERSION    default 2025-06-18
"""

import argparse
import json
import os
import sys
import time

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

MCP_URL = os.environ.get("MCP_URL", "http://192.168.1.102:8009/mcp").rstrip("/")
EMAIL = os.environ.get("CRAPI_EMAIL", "mike1@my.lab")
PASSWORD = os.environ.get("CRAPI_PASSWORD", "Mylab123!")
PROTO = os.environ.get("MCP_PROTOCOL_VERSION", "2025-06-18")
AUTH = os.environ.get("MCP_AUTH_TOKEN", "").strip()

BASE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
if AUTH:
    BASE_HEADERS["Authorization"] = f"Bearer {AUTH}"


def _parse_body(resp):
    """Return the JSON-RPC object whether the reply is application/json or SSE."""
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except Exception:
                    pass
        return {}
    try:
        return resp.json()
    except Exception:
        return {}


def _rpc(session, sid, method, params=None, notification=False, rid=1):
    headers = dict(BASE_HEADERS)
    headers["MCP-Protocol-Version"] = PROTO
    if sid:
        headers["Mcp-Session-Id"] = sid
    payload = {"jsonrpc": "2.0", "method": method}
    if not notification:
        payload["id"] = rid
    if params is not None:
        payload["params"] = params
    return session.post(MCP_URL, headers=headers, data=json.dumps(payload), timeout=15)


def _open_sse(session, sid, log):
    """Open the GET /mcp SSE stream, exactly like a real MCP client (mcp-remote).

    This is the one thing a POST-only generator was missing. A real Streamable
    HTTP client opens a GET /mcp server->client SSE stream after initialize, and
    some sensors key MCP classification on seeing that GET stream — not just the
    POSTs. Without it, the sensor may observe the traffic but not fingerprint it
    as MCP. We open the stream with the real session id, read briefly, and close.
    """
    headers = dict(BASE_HEADERS)
    headers["Accept"] = "text/event-stream"
    headers["MCP-Protocol-Version"] = PROTO
    if sid:
        headers["Mcp-Session-Id"] = sid
    try:
        # stream=True returns as soon as the 200 + headers arrive; we do NOT read
        # the body (an SSE stream is held open with no data, so reading it would
        # just block until timeout). The sensor sees the GET + 200 on the wire
        # regardless — so grab the status and close immediately.
        r = session.get(MCP_URL, headers=headers, stream=True, timeout=(10, 5))
        log(f"GET /mcp (SSE) -> {r.status_code}")
        r.close()
        return r.status_code < 400
    except requests.exceptions.ReadTimeout:
        log("GET /mcp (SSE) -> opened (read timeout, expected)")
        return True
    except Exception as e:
        # benign note, not an error — the GET stream is best-effort
        log(f"GET /mcp (SSE) -> note: {e}")
        return True


def run_cycle(log):
    s = requests.Session()
    ok = 0
    errors = 0

    # 1. initialize (server issues the real Mcp-Session-Id here)
    try:
        r = _rpc(s, None, "initialize", {
            "protocolVersion": PROTO,
            "capabilities": {},
            "clientInfo": {"name": "mcp-heartbeat", "version": "1.0"},
        }, rid=1)
    except Exception as e:
        log(f"initialize FAILED: {e}", err=True)
        return False
    sid = r.headers.get("mcp-session-id") or r.headers.get("Mcp-Session-Id")
    ct = r.headers.get("content-type", "")
    log(f"initialize     -> {r.status_code}  session={sid}  ({ct})")
    if r.status_code >= 400 or not sid:
        log(f"initialize did not return a session id (status {r.status_code})", err=True)
        return False
    ok += 1

    # 2. notifications/initialized (required by spec before normal operation)
    try:
        r = _rpc(s, sid, "notifications/initialized", notification=True)
        log(f"initialized    -> {r.status_code}")
    except Exception as e:
        log(f"initialized notification failed: {e}", err=True)

    # 2b. open the GET /mcp SSE stream like a real client (mcp-remote does this)
    _open_sse(s, sid, log)

    # 3. tools/list
    try:
        r = _rpc(s, sid, "tools/list", {}, rid=2)
        tools = _parse_body(r).get("result", {}).get("tools", [])
        log(f"tools/list     -> {r.status_code}  ({len(tools)} tools)")
        ok += 1
    except Exception as e:
        log(f"tools/list failed: {e}", err=True)
        errors += 1

    # 4. a few tools/call — login (keeps the crAPI session warm) then reads.
    #    Even if a call errors at the crAPI layer, it is still a valid MCP
    #    tools/call and counts as qualifying traffic.
    calls = [
        ("login", {"email": EMAIL, "password": PASSWORD}),
        ("get_recent_posts", {}),
        ("get_products", {}),
        ("get_user_dashboard", {}),
    ]
    rid = 3
    for name, args in calls:
        try:
            r = _rpc(s, sid, "tools/call", {"name": name, "arguments": args}, rid=rid)
            log(f"tools/call {name:<18} -> {r.status_code}")
            ok += 1 if r.status_code < 400 else 0
            errors += 0 if r.status_code < 400 else 1
        except Exception as e:
            log(f"tools/call {name} failed: {e}", err=True)
            errors += 1
        rid += 1

    log(f"cycle done: ok={ok} errors={errors} session={sid}")
    return errors == 0


def main():
    ap = argparse.ArgumentParser(description="MCP heartbeat / traffic keeper")
    ap.add_argument("--loop", action="store_true", help="run forever instead of one cycle")
    ap.add_argument("--interval", type=float, default=45.0, help="seconds between cycles in --loop mode")
    ap.add_argument("--rounds", type=int, default=1, help="number of sessions per cron invocation (default 1; use 10+ to drive enough volume to keep the Noname score high between runs)")
    ap.add_argument("--quiet", action="store_true", help="suppress normal output; print only errors (cron-friendly)")
    ap.add_argument("--close", action="store_true", help="send DELETE /mcp at end (NOT recommended; can untag)")
    args = ap.parse_args()

    ts = lambda: time.strftime("%Y-%m-%d %H:%M:%S")

    def log(msg, err=False):
        if err:
            print(f"[{ts()}] ERROR {msg}", file=sys.stderr, flush=True)
        elif not args.quiet:
            print(f"[{ts()}] {msg}", flush=True)

    if not args.quiet:
        log(f"heartbeat -> {MCP_URL}")

    def once():
        healthy = run_cycle(log)
        if args.close:
            # opt-in only; documented as risky for tagging
            try:
                requests.delete(MCP_URL, headers=BASE_HEADERS, timeout=10)
                log("sent DELETE /mcp (--close)")
            except Exception as e:
                log(f"DELETE failed: {e}", err=True)
        return healthy

    if args.loop:
        try:
            while True:
                once()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            log("stopped.")
    else:
        rounds = max(1, args.rounds)
        ok = True
        for n in range(rounds):
            if rounds > 1 and not args.quiet:
                log(f"--- round {n + 1}/{rounds} ---")
            ok = once() and ok
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
