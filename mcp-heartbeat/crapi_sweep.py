#!/usr/bin/env python3
"""
crapi_sweep.py — drive EVERY crAPI endpoint through the MCP server, no Claude.

This is the full-coverage sibling of mcp_heartbeat.py. Instead of a few tool calls
it exercises the entire crAPI tool surface via MCP `tools/call`, so the MCP server
proxies to every real crAPI endpoint — reproducing exactly what a Claude-driven
sweep does, but from a plain cron job / loop. It keeps the MCP tag warm AND
generates full downstream crAPI API traffic.

It threads the real Mcp-Session-Id, sends recognized MCP methods only, and never
sends DELETE /mcp (that teardown packet can untag the API under IC-75487).

Two-phase per cycle so it survives lab resets:
  1. login, then read endpoints that also HARVEST live ids (vehicle uuid, a post
     id, an order id) from the responses;
  2. call the remaining endpoints using those harvested ids (falling back to
     sensible defaults if harvesting failed).

Modes:
  --mode reads   login + all GET/read endpoints + coupon check (idempotent; best
                 for tight loops / cron — creates no new data)
  --mode all     everything, including create_post / add_product / create_order /
                 mechanic_signup / change_email / etc. (writes accumulate lab data)

Usage:
  python3 crapi_sweep.py                          # one full 'all' sweep, then exit
  python3 crapi_sweep.py --mode reads             # safe, no writes
  python3 crapi_sweep.py --loop --interval 60 --mode reads
  MCP_URL=http://192.168.1.102:8009/mcp python3 crapi_sweep.py
  for i in $(seq 1000); do python3 crapi_sweep.py --mode reads --quiet; sleep 2; done

Env (same as mcp_heartbeat.py):
  MCP_URL (default http://192.168.1.102:8009/mcp), CRAPI_EMAIL, CRAPI_PASSWORD,
  MCP_AUTH_TOKEN, MCP_PROTOCOL_VERSION
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

BASE_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
if AUTH:
    BASE_HEADERS["Authorization"] = f"Bearer {AUTH}"

# defaults used if id-harvesting fails (stable crAPI seed values)
DEFAULT_VEHICLE = "1100c050-1163-4552-bd87-da793ef981e7"
DEFAULT_VIN = "95LZ0P2VY4F03S9Z8"


def _parse_body(resp):
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


def _inner(body):
    """Extract the crAPI JSON payload from an MCP tools/call result."""
    try:
        content = body.get("result", {}).get("content", [])
        if content and content[0].get("type") == "text":
            return json.loads(content[0]["text"])
    except Exception:
        pass
    return None


class Client:
    def __init__(self, log):
        self.s = requests.Session()
        self.sid = None
        self.rid = 0
        self.log = log
        self.ok = 0
        self.err = 0

    def _next(self):
        self.rid += 1
        return self.rid

    def _rpc(self, method, params=None, notification=False):
        headers = dict(BASE_HEADERS)
        headers["MCP-Protocol-Version"] = PROTO
        if self.sid:
            headers["Mcp-Session-Id"] = self.sid
        payload = {"jsonrpc": "2.0", "method": method}
        if not notification:
            payload["id"] = self._next()
        if params is not None:
            payload["params"] = params
        return self.s.post(MCP_URL, headers=headers, data=json.dumps(payload), timeout=20)

    def open_sse(self):
        """Open the GET /mcp SSE stream like a real MCP client (mcp-remote).

        A real Streamable HTTP client opens this server->client stream after
        initialize; some sensors key MCP classification on seeing it, not just the
        POSTs. We open it with the real session id, read briefly, then close.
        """
        headers = dict(BASE_HEADERS)
        headers["Accept"] = "text/event-stream"
        headers["MCP-Protocol-Version"] = PROTO
        if self.sid:
            headers["Mcp-Session-Id"] = self.sid
        try:
            # stream=True returns as soon as the 200 + headers arrive; we do NOT
            # read the body (an SSE stream is held open with no data, so reading
            # it would just block until timeout). The sensor sees the GET + 200 on
            # the wire regardless of whether we drain the stream — so grab the
            # status and close immediately.
            r = self.s.get(MCP_URL, headers=headers, stream=True, timeout=(10, 5))
            self.log(f"GET /mcp (SSE) -> {r.status_code}")
            r.close()
        except requests.exceptions.ReadTimeout:
            self.log("GET /mcp (SSE) -> opened (read timeout, expected)")
        except Exception as e:
            # a benign note, not an error — the GET stream is best-effort
            self.log(f"GET /mcp (SSE) -> note: {e}")

    def handshake(self):
        r = self._rpc("initialize", {
            "protocolVersion": PROTO, "capabilities": {},
            "clientInfo": {"name": "crapi-sweep", "version": "1.0"},
        })
        self.sid = r.headers.get("mcp-session-id") or r.headers.get("Mcp-Session-Id")
        self.log(f"initialize     -> {r.status_code}  session={self.sid}")
        if r.status_code >= 400 or not self.sid:
            return False
        self._rpc("notifications/initialized", notification=True)
        self.open_sse()  # open the GET /mcp SSE stream like a real client
        r = self._rpc("tools/list", {})
        n = len(_parse_body(r).get("result", {}).get("tools", []))
        self.log(f"tools/list     -> {r.status_code}  ({n} tools)")
        return True

    def call(self, name, args=None):
        r = self._rpc("tools/call", {"name": name, "arguments": args or {}})
        body = _parse_body(r)
        inner = _inner(body)
        good = r.status_code < 400
        self.ok += 1 if good else 0
        self.err += 0 if good else 1
        self.log(f"tools/call {name:<20} -> {r.status_code}")
        return inner


def run_cycle(log, mode):
    tok = str(int(time.time()))
    c = Client(log)
    if not c.handshake():
        log("handshake failed", err=True)
        return False

    # ── login ───────────────────────────────────────────────────────────────────
    c.call("login", {"email": EMAIL, "password": PASSWORD})

    # ── phase 1: reads that harvest live ids ─────────────────────────────────────
    c.call("get_user_dashboard")
    vehicles = c.call("get_vehicles")
    vuuid = DEFAULT_VEHICLE
    try:
        if isinstance(vehicles, list) and vehicles:
            vuuid = vehicles[0].get("uuid", DEFAULT_VEHICLE)
    except Exception:
        pass

    posts = c.call("get_recent_posts")
    post_id = None
    try:
        plist = posts.get("posts", []) if isinstance(posts, dict) else []
        if plist:
            post_id = plist[0].get("id")
    except Exception:
        pass

    orders = c.call("get_all_orders")
    order_id = 1
    try:
        olist = orders.get("orders", []) if isinstance(orders, dict) else []
        if olist:
            order_id = olist[0].get("id", 1)
    except Exception:
        pass

    c.call("get_vehicle_location", {"vehicle_id": vuuid})
    c.call("get_vehicle_details", {"vehicle_id": vuuid})       # known 404 (tool/spec)
    c.call("get_products")
    c.call("get_mechanics")
    c.call("get_service_requests")
    c.call("check_coupon", {"coupon_code": "TRAC075"})
    c.call("get_report", {"report_id": 1})                     # BOLA demo
    c.call("get_order", {"order_id": 1})                       # BOLA demo (Adam's)
    if post_id:
        c.call("get_post", {"post_id": post_id})
    c.call("get_all_users")                                    # known 404 (tool/spec)

    if mode == "reads":
        log(f"cycle done (reads): ok={c.ok} err={c.err}")
        return True

    # ── phase 2: writes / state-changing (mode == all) ───────────────────────────
    c.call("create_post", {"title": f"sweep {tok}", "content": f"automated sweep {tok}"})
    if post_id:
        c.call("post_comment", {"post_id": post_id, "content": f"sweep comment {tok}"})
    c.call("add_product", {"name": f"Sweep Part {tok}", "price": 9.99,
                           "image_url": "https://example.com/part.png"})
    new_order = c.call("create_order", {"product_id": 1, "quantity": 1})
    oid = order_id
    try:
        if isinstance(new_order, dict) and "id" in new_order:
            oid = new_order["id"]
    except Exception:
        pass
    c.call("return_order", {"order_id": oid})
    c.call("mechanic_signup", {"name": f"Sweep Mech {tok}", "email": f"sweep-{tok}@my.lab",
                               "number": "555-000-0000", "password": PASSWORD,
                               "mechanic_code": f"TRAC_SWEEP_{tok}"})
    c.call("change_email", {"old_email": EMAIL, "new_email": f"mike1-{tok}@my.lab"})
    c.call("reset_password", {"email": EMAIL})
    c.call("verify_email_token", {"email": EMAIL, "token": "000000"})   # expected 500 (dummy)
    c.call("verify_otp", {"email": EMAIL, "otp": "0000", "password": PASSWORD})  # expected 500
    c.call("update_video_name", {"video_id": 0, "videoName": f"vid-{tok}",
                                 "available_credit": 99999})            # expected 404
    c.call("request_service", {"mechanic_code": "TRAC_JHN", "vin": DEFAULT_VIN,
                               "problem_details": "sweep"})             # expected 400 (tool/spec)
    c.call("receive_report", {"mechanic_code": "TRAC_JHN",
                              "report_link": "http://example.com/report",
                              "status": "Finished"})                    # expected 405 (tool/spec)

    log(f"cycle done (all): ok={c.ok} err={c.err}")
    return True


def _run_loop(log, mode, interval, max_rounds):
    """Long-lived session loop: initialize ONCE, reuse until the session expires."""
    n = 0
    while True:
        tok = str(int(time.time()))
        c = Client(log)
        if not c.handshake():
            log(f"handshake failed — retry in {interval}s", err=True)
            time.sleep(interval)
            continue
        log(f"session={c.sid}  (long-lived, reusing until expired)")

        # Reuse this session for repeated sweep cycles.
        cycle = 0
        while True:
            n += 1
            cycle += 1
            tok = str(int(time.time()))
            log(f"--- cycle {n} (session cycle {cycle}) ---")

            # Check if session is still alive with a tools/list probe.
            r = c._rpc("tools/list", {})
            if r.status_code == 404:
                log("session expired — re-initializing")
                break  # outer while: re-handshake

            # Run the sweep, passing the existing Client (which carries the session).
            ok_before, err_before = c.ok, c.err
            _sweep_with_client(c, tok, mode)
            log(f"cycle done ({mode}): ok={c.ok - ok_before} err={c.err - err_before}")

            if max_rounds and n >= max_rounds:
                return
            time.sleep(interval)


def _sweep_with_client(c, tok, mode):
    """Run one sweep cycle using an already-initialized Client."""
    c.call("login", {"email": EMAIL, "password": PASSWORD})

    # phase 1: reads + id harvesting
    c.call("get_user_dashboard")
    vehicles = c.call("get_vehicles")
    vuuid = DEFAULT_VEHICLE
    try:
        if isinstance(vehicles, list) and vehicles:
            vuuid = vehicles[0].get("uuid", DEFAULT_VEHICLE)
    except Exception:
        pass

    posts = c.call("get_recent_posts")
    post_id = None
    try:
        plist = posts.get("posts", []) if isinstance(posts, dict) else []
        if plist:
            post_id = plist[0].get("id")
    except Exception:
        pass

    orders = c.call("get_all_orders")
    order_id = 1
    try:
        olist = orders.get("orders", []) if isinstance(orders, dict) else []
        if olist:
            order_id = olist[0].get("id", 1)
    except Exception:
        pass

    c.call("get_vehicle_location", {"vehicle_id": vuuid})
    c.call("get_vehicle_details", {"vehicle_id": vuuid})
    c.call("get_products")
    c.call("get_mechanics")
    c.call("get_service_requests")
    c.call("check_coupon", {"coupon_code": "TRAC075"})
    c.call("get_report", {"report_id": 1})
    c.call("get_order", {"order_id": 1})
    if post_id:
        c.call("get_post", {"post_id": post_id})
    c.call("get_all_users")

    if mode == "reads":
        return

    # phase 2: writes (mode == all)
    c.call("create_post", {"title": f"sweep {tok}", "content": f"automated sweep {tok}"})
    if post_id:
        c.call("post_comment", {"post_id": post_id, "content": f"sweep comment {tok}"})
    c.call("add_product", {"name": f"Sweep Part {tok}", "price": 9.99,
                           "image_url": "https://example.com/part.png"})
    new_order = c.call("create_order", {"product_id": 1, "quantity": 1})
    oid = order_id
    try:
        if isinstance(new_order, dict) and "id" in new_order:
            oid = new_order["id"]
    except Exception:
        pass
    c.call("return_order", {"order_id": oid})
    c.call("mechanic_signup", {"name": f"Sweep Mech {tok}", "email": f"sweep-{tok}@my.lab",
                               "number": "555-000-0000", "password": PASSWORD,
                               "mechanic_code": f"TRAC_SWEEP_{tok}"})
    c.call("change_email", {"old_email": EMAIL, "new_email": f"mike1-{tok}@my.lab"})
    c.call("reset_password", {"email": EMAIL})
    c.call("verify_email_token", {"email": EMAIL, "token": "000000"})
    c.call("verify_otp", {"email": EMAIL, "otp": "0000", "password": PASSWORD})
    c.call("update_video_name", {"video_id": 0, "videoName": f"vid-{tok}",
                                 "available_credit": 99999})
    c.call("request_service", {"mechanic_code": "TRAC_JHN", "vin": DEFAULT_VIN,
                               "problem_details": "sweep"})
    c.call("receive_report", {"mechanic_code": "TRAC_JHN",
                              "report_link": "http://example.com/report",
                              "status": "Finished"})


def main():
    ap = argparse.ArgumentParser(description="Drive all crAPI endpoints via MCP, no Claude")
    ap.add_argument("--mode", choices=["reads", "all"], default="all")
    ap.add_argument("--loop", action="store_true",
                    help="run forever with one long-lived session (re-initializes only on 404)")
    ap.add_argument("--interval", type=float, default=60.0)
    ap.add_argument("--rounds", type=int, default=0, help="0 = one cycle (or infinite with --loop)")
    ap.add_argument("--quiet", action="store_true", help="only print errors (cron-friendly)")
    args = ap.parse_args()

    ts = lambda: time.strftime("%Y-%m-%d %H:%M:%S")

    def log(msg, err=False):
        if err:
            print(f"[{ts()}] ERROR {msg}", file=sys.stderr, flush=True)
        elif not args.quiet:
            print(f"[{ts()}] {msg}", flush=True)

    if not args.quiet:
        log(f"crapi-sweep -> {MCP_URL}  mode={args.mode}")

    if args.loop:
        try:
            _run_loop(log, args.mode, args.interval, args.rounds)
        except KeyboardInterrupt:
            log("stopped.")
    else:
        rounds = args.rounds or 1
        healthy = True
        for n in range(rounds):
            if rounds > 1 and not args.quiet:
                log(f"--- cycle {n + 1} ---")
            healthy = run_cycle(log, args.mode) and healthy
        sys.exit(0 if healthy else 1)


if __name__ == "__main__":
    main()
