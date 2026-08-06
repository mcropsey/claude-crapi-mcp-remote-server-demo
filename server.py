"""
crAPI MCP Server
=================
Middleware between Claude and a remote crAPI instance.
Each tool maps to a real crAPI endpoint and demonstrates
a specific OWASP API Top 10 vulnerability.

Target: configured via the CRAPI_BASE environment variable (see crapi-mcp.env).

Demo order
----------
Demo 1 — Module 5 — Data Exposure (API3):   get_user_dashboard, get_recent_posts
  Run first — forum post author objects leak vehicleids used in Demo 2.
Demo 2 — Module 1 — BOLA (API1):            get_vehicles, get_vehicle_location, get_vehicle_details
  Requires vehicle UUIDs harvested from get_recent_posts in Demo 1.
Demo 3 — Module 2 — Broken Auth (API2):     reset_password, verify_otp
  reset_password has no rate limiting; verify_otp has no lockout — together
  they form a complete account takeover chain via OTP brute-force.
Demo 4 — Module 3 — BFLA (API5):            get_all_users
Demo 5 — Module 4 — Mass Assignment (API6): update_video_name
  Attack vector: inject available_credit in the video name update payload.
  There is no role field — earlier docs were wrong.
Demo 6 — Module 6 — SSRF (API7):            check_coupon
  NOTE: In stock crAPI the SSRF lives in request_service
  (POST /workshop/api/merchant/contact_mechanic, mechanic_api field).
  check_coupon hits the coupon validate endpoint and passes the coupon_code
  value directly — use an internal URL as the payload to demonstrate the
  same vulnerability class through this surface.
Community  — Posts:                get_recent_posts, get_post, create_post, post_comment
Workshop   — Shop:                 get_products, add_product, create_order, get_order, get_all_orders, return_order
Workshop   — Mechanic:             get_mechanics, mechanic_signup, get_service_requests, get_report,
                                   request_service, receive_report
Identity   — Signup:               signup
"""

import asyncio
import json
import os
import uuid

import httpx
import uvicorn
from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp import types
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import Receive, Scope, Send

app = Server("crapi")


# ── Load configuration from the env file ────────────────────────────────────────
# crapi-mcp.env is the single place to configure the target. Under systemd it's
# loaded via EnvironmentFile (so this is a harmless no-op there); when running by
# hand (python3 server.py) this makes the server read the SAME file, so the URL
# lives in exactly one place no matter how the server is launched. Variables
# already present in the real environment always win — the file only fills gaps.
def _load_env_file():
    path = os.environ.get("CRAPI_MCP_ENV") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "crapi-mcp.env"
    )
    if not os.path.isfile(path):
        return
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, sep, value = line.partition("=")
            if not sep:
                continue
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file()

# ── Config (all overridable via environment) ────────────────────────────────────
# The crAPI target. Read from the environment, which is populated either by
# systemd's EnvironmentFile or by _load_env_file() above — both read crapi-mcp.env.
# There is intentionally no hardcoded URL here, so the target lives in one place.
# Fail fast if it's still unset (e.g. the env file is missing or has no CRAPI_BASE).
API_BASE = os.environ.get("CRAPI_BASE", "").rstrip("/")
if not API_BASE:
    raise RuntimeError(
        "CRAPI_BASE is not set. Configure the target URL in the environment "
        "(e.g. CRAPI_BASE=https://crapi.cropseyit.com in crapi-mcp.env)."
    )

# Where this MCP server listens. 0.0.0.0 so it's reachable on the LAN/VPN.
HOST = os.environ.get("MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("MCP_PORT", "8009"))
MCP_PATH = os.environ.get("MCP_PATH", "/mcp")

# Optional: gate the MCP endpoint itself with a static bearer token so random
# hosts on the network can't drive the attack tools. Leave unset to disable.
# If set, the client (mcp-remote) must send: Authorization: Bearer <this value>.
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")

# ── MCP session identity ──────────────────────────────────────────────────────────
# TRANSPORT: stateless=True (see StreamableHTTPSessionManager below).
# All GETs are intercepted in the ASGI layer and return 200 (so Noname never sees
# a 405 from the SDK). Every /mcp response carries the PINNED session ID below via
# the _wrap_send_inject_session_id wrapper so Noname's sensor always maps this
# traffic to the same Inventory entry, regardless of how many times clients
# reconnect or the service restarts.
#
# History of iterations:
#   v1 — stateless + manual header injection (pinned id): broke on GET /mcp → 405
#          (stateless SDK rejects all GETs; the 405 was a non-qualifying packet that
#          untags the API under IC-75487).
#   v2 — stateful (stateless=False): fixed the GET → 405 by letting the SDK own the
#          SSE stream, but introduced a NEW problem: stateful mode mints a FRESH
#          random mcp-session-id on every `initialize`. Every heartbeat/sweep cycle,
#          and every Claude Desktop reconnect, gets a different id → Noname treats
#          each as a brand-new server and drops the old tool inventory.
#   v3 (current) — stateless=True + GET interceptor for ALL GETs + ASGI response
#          wrapper that injects the pinned id on every POST response. Stateless mode
#          means no session validation, so clients can reconnect freely without
#          getting 404 "expired session". The pinned id ensures Noname sees one
#          stable identity. The GET interceptor returns 200 (not 405), so GETs
#          from mcp-remote are always qualifying traffic.
#
# MCP_SESSION_ID: set in crapi-mcp.env to survive restarts. If unset, a random id
# is minted once per process (stable for that run, but not across restarts).
MCP_PROTOCOL_VERSION = os.environ.get("MCP_PROTOCOL_VERSION", "2025-06-18")
MCP_SESSION_ID = os.environ.get("MCP_SESSION_ID", "") or uuid.uuid4().hex

# crAPI session token. Seeded from CRAPI_TOKEN if present, but the `login` tool
# updates this in-memory at runtime — no file edit or restart needed anymore.
_crapi_token: str = os.environ.get("CRAPI_TOKEN", "")


def auth_headers():
    if _crapi_token:
        return {"Authorization": f"Bearer {_crapi_token}"}
    return {}


# ── Tool definitions ───────────────────────────────────────────────────────────
@app.list_tools()
async def list_tools():
    return [
        # ── Auth ──────────────────────────────────────────────────────────────
        types.Tool(
            name="signup",
            description="Create a new crAPI user account.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name":     {"type": "string",  "description": "Full name"},
                    "email":    {"type": "string",  "description": "Email address"},
                    "number":   {"type": "string",  "description": "Phone number"},
                    "password": {"type": "string",  "description": "Password"},
                },
                "required": ["name", "email", "number", "password"],
            },
        ),
        types.Tool(
            name="login",
            description="Log in to crAPI and return a JWT token. The token is stored in-memory and used automatically for subsequent authenticated tools — no restart needed.",
            inputSchema={
                "type": "object",
                "properties": {
                    "email":    {"type": "string", "description": "User email"},
                    "password": {"type": "string", "description": "User password"},
                },
                "required": ["email", "password"],
            },
        ),
        types.Tool(
            name="reset_password",
            description="Module 2 — Broken Auth: trigger a password reset for any email. Demonstrates lack of rate limiting.",
            inputSchema={
                "type": "object",
                "properties": {
                    "email": {"type": "string", "description": "Target email address"},
                },
                "required": ["email"],
            },
        ),
        types.Tool(
            name="verify_otp",
            description="Module 2 — Broken Auth: verify OTP and set a new password. Demonstrates OTP brute-force (no lockout).",
            inputSchema={
                "type": "object",
                "properties": {
                    "email":    {"type": "string", "description": "User email"},
                    "otp":      {"type": "string", "description": "OTP code (3-4 digits)"},
                    "password": {"type": "string", "description": "New password"},
                },
                "required": ["email", "otp", "password"],
            },
        ),
        types.Tool(
            name="change_email",
            description="Send an email-change token to a new address. Requires auth.",
            inputSchema={
                "type": "object",
                "properties": {
                    "old_email": {"type": "string", "description": "Current email"},
                    "new_email": {"type": "string", "description": "New email to change to"},
                },
                "required": ["old_email", "new_email"],
            },
        ),
        types.Tool(
            name="verify_email_token",
            description="Verify the email-change token sent to the new address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "email": {"type": "string", "description": "New email address"},
                    "token": {"type": "string", "description": "Token received at new email"},
                },
                "required": ["email", "token"],
            },
        ),

        # ── User / Dashboard ──────────────────────────────────────────────────
        types.Tool(
            name="get_user_dashboard",
            description="Module 5 — Excessive Data Exposure: fetch the current user dashboard. Observe all fields returned including sensitive ones not needed by the UI.",
            inputSchema={"type": "object", "properties": {}},
        ),

        # ── Vehicles ──────────────────────────────────────────────────────────
        types.Tool(
            name="get_vehicles",
            description="Module 1 — BOLA setup: get the list of vehicles registered to the current authenticated user.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_vehicle_location",
            description="Module 1 — BOLA: get the location of any vehicle by UUID. No ownership check — returns any vehicle's location.",
            inputSchema={
                "type": "object",
                "properties": {
                    "vehicle_id": {"type": "string", "description": "Vehicle UUID to look up"},
                },
                "required": ["vehicle_id"],
            },
        ),
        types.Tool(
            name="get_vehicle_details",
            description="Module 1 — BOLA: get full details of any vehicle by UUID from the community endpoint.",
            inputSchema={
                "type": "object",
                "properties": {
                    "vehicle_id": {"type": "string", "description": "Vehicle UUID to look up"},
                },
                "required": ["vehicle_id"],
            },
        ),

        # ── Admin ─────────────────────────────────────────────────────────────
        types.Tool(
            name="get_all_users",
            description="Module 3 — BFLA: call the admin endpoint that lists all users. A normal user should not have access — no role check enforced.",
            inputSchema={"type": "object", "properties": {}},
        ),

        # ── Video ─────────────────────────────────────────────────────────────
        types.Tool(
            name="update_video_name",
            description=(
                "Module 4 — Mass Assignment: update the video name on the user profile. "
                "Try passing available_credit with a high value to demonstrate the vulnerability."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "video_id":         {"type": "integer", "description": "Video ID from the dashboard"},
                    "videoName":        {"type": "string",  "description": "New video name"},
                    "available_credit": {"type": "number",  "description": "ATTACK: inject a credit balance, e.g. 9999"},
                },
                "required": ["video_id", "videoName"],
            },
        ),

        # ── Community / Posts ─────────────────────────────────────────────────
        types.Tool(
            name="get_recent_posts",
            description=(
                "Module 5 — Excessive Data Exposure: fetch the most recent forum posts. "
                "Each post's author object leaks vehicleid and email — the vehicle UUIDs "
                "are used directly in the Module 1 BOLA attack."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_post",
            description="Community: get a specific forum post by its ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "post_id": {"type": "string", "description": "Post ID"},
                },
                "required": ["post_id"],
            },
        ),
        types.Tool(
            name="create_post",
            description="Community: create a new forum post.",
            inputSchema={
                "type": "object",
                "properties": {
                    "title":   {"type": "string", "description": "Post title"},
                    "content": {"type": "string", "description": "Post content"},
                },
                "required": ["title", "content"],
            },
        ),
        types.Tool(
            name="post_comment",
            description="Community: add a comment to an existing forum post.",
            inputSchema={
                "type": "object",
                "properties": {
                    "post_id": {"type": "string", "description": "Post ID to comment on"},
                    "content": {"type": "string", "description": "Comment content"},
                },
                "required": ["post_id", "content"],
            },
        ),

        # ── Workshop / Shop ───────────────────────────────────────────────────
        types.Tool(
            name="get_products",
            description="Shop: get all available products and the user's current credit balance.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="add_product",
            description="Shop: add a new product to the catalog (admin-level action).",
            inputSchema={
                "type": "object",
                "properties": {
                    "name":      {"type": "string", "description": "Product name"},
                    "price":     {"type": "string", "description": "Price in decimal format, e.g. '9.99'"},
                    "image_url": {"type": "string", "description": "URL of product image"},
                },
                "required": ["name", "price", "image_url"],
            },
        ),
        types.Tool(
            name="create_order",
            description="Shop: place an order for a product.",
            inputSchema={
                "type": "object",
                "properties": {
                    "product_id": {"type": "integer", "description": "Product ID to order"},
                    "quantity":   {"type": "integer", "description": "Quantity to order"},
                },
                "required": ["product_id", "quantity"],
            },
        ),
        types.Tool(
            name="get_order",
            description="Shop — BOLA: get order details by order ID. No ownership check.",
            inputSchema={
                "type": "object",
                "properties": {
                    "order_id": {"type": "integer", "description": "Order ID"},
                },
                "required": ["order_id"],
            },
        ),
        types.Tool(
            name="get_all_orders",
            description="Shop: get all past orders for the current user.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="return_order",
            description="Shop: return an order by order ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "order_id": {"type": "integer", "description": "Order ID to return"},
                },
                "required": ["order_id"],
            },
        ),

        # ── Workshop / Coupon ─────────────────────────────────────────────────
        # NOTE: The coupon endpoint is used here to demonstrate SSRF. In stock
        # crAPI the canonical SSRF surface is request_service (contact_mechanic),
        # but the coupon validate endpoint passes coupon_code directly into a
        # server-side HTTP call with no URL validation — same vulnerability class.
        # Supply an internal URL (e.g. http://localhost:8888) as the coupon_code
        # to have the server probe its own network on your behalf.
        types.Tool(
            name="check_coupon",
            description=(
                "Module 6 — SSRF: pass a coupon code to the validate endpoint. "
                "The server makes a server-side HTTP call using the coupon_code value "
                "with no URL validation — supply an internal address (e.g. "
                "http://localhost:8888 or http://169.254.169.254/latest/meta-data) "
                "to probe the server's internal network. A real coupon code (e.g. "
                "TRAC075) works normally and demonstrates the intended flow."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "coupon_code": {"type": "string", "description": "Coupon code (normal flow) or internal URL (SSRF attack)"},
                },
                "required": ["coupon_code"],
            },
        ),

        # ── Workshop / Mechanic ───────────────────────────────────────────────
        types.Tool(
            name="get_mechanics",
            description="Workshop: get all available mechanics.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="mechanic_signup",
            description="Workshop: register a new mechanic account.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name":          {"type": "string", "description": "Mechanic full name"},
                    "email":         {"type": "string", "description": "Mechanic email"},
                    "number":        {"type": "string", "description": "Phone number"},
                    "password":      {"type": "string", "description": "Password"},
                    "mechanic_code": {"type": "string", "description": "Unique mechanic code"},
                },
                "required": ["name", "email", "number", "password", "mechanic_code"],
            },
        ),
        types.Tool(
            name="request_service",
            description=(
                "Workshop: request a mechanic service for a vehicle. "
                "NOTE: In stock crAPI this is the canonical SSRF endpoint — "
                "POST /workshop/api/merchant/contact_mechanic accepts a mechanic_api "
                "URL field that the server fetches server-side with no validation. "
                "This MCP lab demonstrates SSRF via check_coupon instead."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "mechanic_code":   {"type": "string", "description": "Mechanic code (e.g. TRAC_MECH1)"},
                    "problem_details": {"type": "string", "description": "Description of the problem"},
                    "vin":             {"type": "string", "description": "Vehicle VIN"},
                },
                "required": ["mechanic_code", "problem_details", "vin"],
            },
        ),
        types.Tool(
            name="get_service_requests",
            description="Workshop: get all service requests assigned to the current mechanic.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_report",
            description="Workshop — BOLA: get a service report by report ID. No ownership check.",
            inputSchema={
                "type": "object",
                "properties": {
                    "report_id": {"type": "integer", "description": "Report/service-request ID"},
                },
                "required": ["report_id"],
            },
        ),
        types.Tool(
            name="receive_report",
            description="Workshop: receive/acknowledge a mechanic service report.",
            inputSchema={
                "type": "object",
                "properties": {
                    "mechanic_code": {"type": "string", "description": "Mechanic code"},
                    "status":        {"type": "string", "description": "New status (e.g. 'Finished')"},
                    "report_link":   {"type": "string", "description": "URL of the report"},
                },
                "required": ["mechanic_code", "status", "report_link"],
            },
        ),
    ]


# ── Tool execution ──────────────────────────────────────────────────────────────
@app.call_tool()
async def call_tool(name: str, arguments: dict):
    async with httpx.AsyncClient(timeout=60.0) as client:

        def ok(data):
            return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

        def err(e):
            if isinstance(e, httpx.HTTPStatusError):
                return [types.TextContent(type="text", text=f"Error {e.response.status_code}: {e.response.text}")]
            return [types.TextContent(type="text", text=f"Request failed: {e}")]

        # ── Auth ───────────────────────────────────────────────────────────────
        if name == "signup":
            try:
                r = await client.post(
                    f"{API_BASE}/identity/api/auth/signup",
                    json={
                        "name":     arguments["name"],
                        "email":    arguments["email"],
                        "number":   arguments["number"],
                        "password": arguments["password"],
                    },
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "login":
            try:
                r = await client.post(
                    f"{API_BASE}/identity/api/auth/login",
                    json={"email": arguments["email"], "password": arguments["password"]},
                )
                r.raise_for_status()
                token = r.json().get("token", "")
                # Store the token in-process so every subsequent authed tool call
                # uses it automatically. No file edit, no restart required.
                global _crapi_token
                _crapi_token = token
                return [types.TextContent(type="text", text=(
                    "Login successful. The session token is now active for this "
                    "server and will be used automatically for authenticated tools.\n\n"
                    f"Token (for reference):\n{token}"
                ))]
            except Exception as e:
                return err(e)

        if name == "reset_password":
            try:
                r = await client.post(
                    f"{API_BASE}/identity/api/auth/forget-password",
                    json={"email": arguments["email"]},
                )
                return [types.TextContent(type="text", text=f"Status {r.status_code}: {r.text}")]
            except Exception as e:
                return err(e)

        if name == "verify_otp":
            try:
                r = await client.post(
                    f"{API_BASE}/identity/api/auth/v3/check-otp",
                    json={
                        "email":    arguments["email"],
                        "otp":      arguments["otp"],
                        "password": arguments["password"],
                    },
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "change_email":
            try:
                r = await client.post(
                    f"{API_BASE}/identity/api/v2/user/change-email",
                    headers=auth_headers(),
                    json={"old_email": arguments["old_email"], "new_email": arguments["new_email"]},
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "verify_email_token":
            try:
                r = await client.post(
                    f"{API_BASE}/identity/api/v2/user/verify-email-token",
                    headers=auth_headers(),
                    json={"email": arguments["email"], "token": arguments["token"]},
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        # ── Dashboard ──────────────────────────────────────────────────────────
        if name == "get_user_dashboard":
            try:
                r = await client.get(
                    f"{API_BASE}/identity/api/v2/user/dashboard",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        # ── Vehicles ───────────────────────────────────────────────────────────
        if name == "get_vehicles":
            try:
                r = await client.get(
                    f"{API_BASE}/identity/api/v2/vehicle/vehicles",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "get_vehicle_location":
            try:
                r = await client.get(
                    f"{API_BASE}/identity/api/v2/vehicle/{arguments['vehicle_id']}/location",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "get_vehicle_details":
            try:
                r = await client.get(
                    f"{API_BASE}/community/api/v2/vehicle/{arguments['vehicle_id']}",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        # ── Admin ──────────────────────────────────────────────────────────────
        if name == "get_all_users":
            try:
                r = await client.get(
                    f"{API_BASE}/identity/api/v2/admin/users",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        # ── Video ──────────────────────────────────────────────────────────────
        if name == "update_video_name":
            try:
                payload = {"id": arguments["video_id"], "videoName": arguments["videoName"]}
                if "available_credit" in arguments:
                    payload["available_credit"] = arguments["available_credit"]
                r = await client.put(
                    f"{API_BASE}/identity/api/v2/user/videos/{arguments['video_id']}",
                    headers=auth_headers(),
                    json=payload,
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        # ── Community / Posts ──────────────────────────────────────────────────
        if name == "get_recent_posts":
            try:
                r = await client.get(
                    f"{API_BASE}/community/api/v2/community/posts/recent",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "get_post":
            try:
                r = await client.get(
                    f"{API_BASE}/community/api/v2/community/posts/{arguments['post_id']}",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "create_post":
            try:
                r = await client.post(
                    f"{API_BASE}/community/api/v2/community/posts",
                    headers=auth_headers(),
                    json={"title": arguments["title"], "content": arguments["content"]},
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "post_comment":
            try:
                r = await client.post(
                    f"{API_BASE}/community/api/v2/community/posts/{arguments['post_id']}/comment",
                    headers=auth_headers(),
                    json={"content": arguments["content"]},
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        # ── Shop ───────────────────────────────────────────────────────────────
        if name == "get_products":
            try:
                r = await client.get(
                    f"{API_BASE}/workshop/api/shop/products",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "add_product":
            try:
                r = await client.post(
                    f"{API_BASE}/workshop/api/shop/products",
                    headers=auth_headers(),
                    json={
                        "name":      arguments["name"],
                        "price":     arguments["price"],
                        "image_url": arguments["image_url"],
                    },
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "create_order":
            try:
                r = await client.post(
                    f"{API_BASE}/workshop/api/shop/orders",
                    headers=auth_headers(),
                    json={"product_id": arguments["product_id"], "quantity": arguments["quantity"]},
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "get_order":
            try:
                r = await client.get(
                    f"{API_BASE}/workshop/api/shop/orders/{arguments['order_id']}",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "get_all_orders":
            try:
                r = await client.get(
                    f"{API_BASE}/workshop/api/shop/orders/all",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "return_order":
            try:
                r = await client.post(
                    f"{API_BASE}/workshop/api/shop/orders/return_order",
                    headers=auth_headers(),
                    params={"order_id": arguments["order_id"]},
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        # ── Coupon (SSRF demo) ─────────────────────────────────────────────────
        # Passes coupon_code directly to the validate endpoint. Supply an internal
        # URL instead of a coupon code to have the server probe its own network.
        if name == "check_coupon":
            try:
                r = await client.post(
                    f"{API_BASE}/community/api/v2/coupon/validate-coupon",
                    headers=auth_headers(),
                    json={"coupon_code": arguments["coupon_code"]},
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        # ── Mechanic ───────────────────────────────────────────────────────────
        if name == "get_mechanics":
            try:
                r = await client.get(
                    f"{API_BASE}/workshop/api/mechanic/",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "mechanic_signup":
            try:
                r = await client.post(
                    f"{API_BASE}/workshop/api/mechanic/signup",
                    json={
                        "name":          arguments["name"],
                        "email":         arguments["email"],
                        "number":        arguments["number"],
                        "password":      arguments["password"],
                        "mechanic_code": arguments["mechanic_code"],
                    },
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "request_service":
            try:
                r = await client.post(
                    f"{API_BASE}/workshop/api/merchant/contact_mechanic",
                    headers=auth_headers(),
                    json={
                        "mechanic_code":   arguments["mechanic_code"],
                        "problem_details": arguments["problem_details"],
                        "vin":             arguments["vin"],
                    },
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "get_service_requests":
            try:
                r = await client.get(
                    f"{API_BASE}/workshop/api/mechanic/service_requests",
                    headers=auth_headers(),
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "get_report":
            try:
                r = await client.get(
                    f"{API_BASE}/workshop/api/mechanic/mechanic_report",
                    headers=auth_headers(),
                    params={"report_id": arguments["report_id"]},
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

        if name == "receive_report":
            try:
                r = await client.post(
                    f"{API_BASE}/workshop/api/mechanic/receive_report",
                    headers=auth_headers(),
                    json={
                        "mechanic_code": arguments["mechanic_code"],
                        "status":        arguments["status"],
                        "report_link":   arguments["report_link"],
                    },
                )
                r.raise_for_status()
                return ok(r.json())
            except Exception as e:
                return err(e)

    return [types.TextContent(type="text", text="Unknown tool")]


# ── Entry point: Streamable HTTP transport ──────────────────────────────────────
# The low-level Server above is unchanged; we just expose it over HTTP instead of
# stdio so Claude Desktop can reach it across the network (via mcp-remote).

session_manager = StreamableHTTPSessionManager(
    app=app,
    event_store=None,     # no resumability store needed for this lab
    json_response=True,   # POST /mcp responses are application/json (not SSE-framed).
                          # Fine for Noname's classifier.
    stateless=True,       # No per-session state or session-id validation. Combined
                          # with _wrap_send_inject_session_id (below) which pins
                          # MCP_SESSION_ID on every response, all clients always
                          # receive the same stable identifier — Noname never sees
                          # "new server". The crAPI token lives in a module global
                          # (not session state), so it survives across tool calls.
                          # Stateless mode also means no 404 "expired session" after
                          # a service restart — clients continue seamlessly.
)

_MCP_PATH = "/" + MCP_PATH.strip("/")


async def _get_ok(scope: Scope, receive: Receive, send: Send) -> None:
    """Return 200 text/event-stream for any GET /mcp, held open until disconnect.

    With stateless=True the SDK would 405 every GET. We intercept ALL GETs here
    and return a proper SSE stream with the pinned MCP markers.

    IMPORTANT: we hold the stream open (more_body=True) and wait for the client
    to disconnect. Closing immediately causes mcp-remote to retry in <1s, flooding
    the server with GET requests (16+/second) and producing anomalous traffic that
    confuses Noname's MCP classifier. A long-lived SSE GET matches what a real
    Streamable HTTP MCP client (mcp-remote) maintains throughout its session.
    """
    headers = [
        (b"content-type", b"text/event-stream"),
        (b"cache-control", b"no-cache"),
        (b"mcp-session-id", MCP_SESSION_ID.encode()),
        (b"mcp-protocol-version", MCP_PROTOCOL_VERSION.encode()),
    ]
    await send({"type": "http.response.start", "status": 200, "headers": headers})
    # Send the opening SSE comment so the client sees a valid stream start.
    await send({"type": "http.response.body", "body": b": ok\n\n", "more_body": True})

    # Hold open: send a keepalive comment every 30 s; close on client disconnect.
    # asyncio.wait_for on receive() gives us the disconnect event without a spin loop.
    while True:
        try:
            msg = await asyncio.wait_for(receive(), timeout=30.0)
            if msg.get("type") == "http.disconnect":
                break
        except asyncio.TimeoutError:
            # Client still connected — send keepalive so the connection doesn't
            # time out in the network path.
            try:
                await send({"type": "http.response.body", "body": b": keepalive\n\n", "more_body": True})
            except Exception:
                break  # send failed — client gone

    await send({"type": "http.response.body", "body": b"", "more_body": False})


def _wrap_send_inject_session_id(send):
    """Wrap the ASGI send callable to pin MCP_SESSION_ID on every POST response.

    The stateless session manager returns no mcp-session-id header of its own.
    We inject (or replace) the pinned value here so every /mcp POST response —
    initialize, tools/list, tools/call, notifications/initialized — carries the
    same stable identifier. Noname keys its inventory entry on this value, so a
    stable ID means tools never disappear between reconnects or service restarts.
    """
    _sid   = MCP_SESSION_ID.encode()
    _proto = MCP_PROTOCOL_VERSION.encode()

    async def patched_send(message):
        if message["type"] == "http.response.start":
            hdrs = [
                (k, v) for k, v in message.get("headers", [])
                if k.lower() not in (b"mcp-session-id", b"mcp-protocol-version")
            ]
            hdrs += [(b"mcp-session-id", _sid), (b"mcp-protocol-version", _proto)]
            message = {**message, "headers": hdrs}
        await send(message)

    return patched_send


# ── LLM / GenAI Endpoints (for Noname discovery) ─────────────────────────────────
# These are mock endpoints that mimic OpenAI-compatible LLM APIs so Noname
# can classify this server as GenAI/LLM in addition to MCP. Responses are
# realistic stubs; they don't do actual inference.

async def llm_chat_completions(scope: Scope, receive: Receive, send: Send) -> None:
    """POST /v1/chat/completions — OpenAI-compatible chat endpoint."""
    try:
        body = await receive()
        payload = json.loads(body.get("body", b"{}"))
    except:
        payload = {}

    response = {
        "id": "chatcmpl-8MltWQnO8qBRlV8z2eKFlwfo",
        "object": "chat.completion",
        "created": 1700000000,
        "model": payload.get("model", "gpt-4"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "This is a mock LLM response from crAPI demo server."
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": len(str(payload.get("messages", []))),
            "completion_tokens": 15,
            "total_tokens": 30
        }
    }
    await JSONResponse(response)(scope, receive, send)


async def llm_embeddings(scope: Scope, receive: Receive, send: Send) -> None:
    """POST /v1/embeddings — OpenAI-compatible embeddings endpoint."""
    response = {
        "object": "list",
        "data": [
            {
                "object": "embedding",
                "embedding": [0.1, -0.05, 0.3] * 258 + [0.15],  # 1536 dims like OpenAI
                "index": 0
            }
        ],
        "model": "text-embedding-3-small",
        "usage": {
            "prompt_tokens": 10,
            "total_tokens": 10
        }
    }
    await JSONResponse(response)(scope, receive, send)


async def llm_completions(scope: Scope, receive: Receive, send: Send) -> None:
    """POST /v1/completions — OpenAI-compatible text completion endpoint."""
    response = {
        "id": "cmpl-8MltXXnO8qBRlV8z2eKFlwfo",
        "object": "text_completion",
        "created": 1700000000,
        "model": "gpt-3.5-turbo",
        "choices": [
            {
                "text": " This is mock completion text from crAPI demo server.",
                "index": 0,
                "logprobs": None,
                "finish_reason": "length"
            }
        ],
        "usage": {
            "prompt_tokens": 8,
            "completion_tokens": 12,
            "total_tokens": 20
        }
    }
    await JSONResponse(response)(scope, receive, send)


async def llm_models(scope: Scope, receive: Receive, send: Send) -> None:
    """GET /v1/models — OpenAI-compatible model listing endpoint."""
    response = {
        "object": "list",
        "data": [
            {"id": "gpt-4", "object": "model", "created": 1687882411, "owned_by": "openai"},
            {"id": "gpt-3.5-turbo", "object": "model", "created": 1677649963, "owned_by": "openai"},
            {"id": "text-embedding-3-small", "object": "model", "created": 1694807822, "owned_by": "openai"},
        ]
    }
    await JSONResponse(response)(scope, receive, send)


async def asgi_app(scope: Scope, receive: Receive, send: Send) -> None:
    """Explicit ASGI dispatcher.

    We route both /mcp and /mcp/ straight to the session manager so the request
    that carries the recognizable /mcp path returns 200 itself. (A Starlette
    Mount 307-redirects /mcp -> /mcp/, which makes API sensors such as Noname see
    only a redirect on /mcp and the 2xx on a separate request, fragmenting the
    MCP API in inventory.)
    """
    typ = scope["type"]

    # Lifespan: keep the session manager's task group running for the app's life.
    if typ == "lifespan":
        async with session_manager.run():
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        return

    if typ != "http":
        return

    path = scope.get("path", "")

    if path == "/healthz":
        await PlainTextResponse("ok")(scope, receive, send)
        return

    if path.rstrip("/") == _MCP_PATH:
        req_headers = dict(scope.get("headers") or [])

        # Optional shared-secret gate on the MCP endpoint itself.
        if MCP_AUTH_TOKEN:
            provided = req_headers.get(b"authorization", b"").decode()
            if provided != f"Bearer {MCP_AUTH_TOKEN}":
                await JSONResponse({"error": "unauthorized"}, status_code=401)(
                    scope, receive, send
                )
                return

        # ALL GETs → pinned 200 SSE (see _get_ok). With stateless=True the SDK
        # would 405 every GET; intercepting here keeps every /mcp response qualifying.
        if scope.get("method", "GET") == "GET":
            await _get_ok(scope, receive, send)
            return

        # POSTs → stateless session manager, wrapped to pin MCP_SESSION_ID on the
        # response so every client (heartbeat, sweep, Claude Desktop) always receives
        # the same stable identifier and Noname never sees a "new server".
        await session_manager.handle_request(
            scope, receive, _wrap_send_inject_session_id(send)
        )
        return

    # ── LLM / GenAI route handling ──────────────────────────────────────────────
    # OpenAI-compatible endpoints for Noname GenAI/LLM discovery
    if path == "/v1/chat/completions":
        await llm_chat_completions(scope, receive, send)
        return
    if path == "/v1/embeddings":
        await llm_embeddings(scope, receive, send)
        return
    if path == "/v1/completions":
        await llm_completions(scope, receive, send)
        return
    if path == "/v1/models":
        await llm_models(scope, receive, send)
        return

    await JSONResponse({"error": "not found"}, status_code=404)(scope, receive, send)


if __name__ == "__main__":
    # Single worker on purpose: the crAPI session token lives in-process memory.
    uvicorn.run(asgi_app, host=HOST, port=PORT, workers=1)
