"""
crAPI MCP Server
=================
Middleware between Claude and a remote crAPI instance.
Each tool maps to a real crAPI endpoint and demonstrates
a specific OWASP API Top 10 vulnerability.

Target: http://192.168.1.101:8888

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

import json
import os

import httpx
import uvicorn
from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp import types
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import Receive, Scope, Send

app = Server("crapi")

# ── Config (all overridable via environment) ────────────────────────────────────
# The crAPI target. Point this at wherever crAPI is reachable FROM the RHEL box.
API_BASE = os.environ.get("CRAPI_BASE", "http://192.168.1.101:8888")

# Where this MCP server listens. 0.0.0.0 so it's reachable on the LAN/VPN.
HOST = os.environ.get("MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("MCP_PORT", "8009"))
MCP_PATH = os.environ.get("MCP_PATH", "/mcp")

# Optional: gate the MCP endpoint itself with a static bearer token so random
# hosts on the network can't drive the attack tools. Leave unset to disable.
# If set, the client (mcp-remote) must send: Authorization: Bearer <this value>.
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")

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
    json_response=True,    # plain JSON responses; simpler for a proxy like this
    stateless=False,       # stateful: server issues an Mcp-Session-Id per session
)

_MCP_PATH = "/" + MCP_PATH.strip("/")


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
        # Optional shared-secret gate on the MCP endpoint itself.
        if MCP_AUTH_TOKEN:
            headers = dict(scope.get("headers") or [])
            provided = headers.get(b"authorization", b"").decode()
            if provided != f"Bearer {MCP_AUTH_TOKEN}":
                await JSONResponse({"error": "unauthorized"}, status_code=401)(
                    scope, receive, send
                )
                return
        await session_manager.handle_request(scope, receive, send)
        return

    await JSONResponse({"error": "not found"}, status_code=404)(scope, receive, send)


if __name__ == "__main__":
    # Single worker on purpose: the crAPI session token lives in-process memory.
    uvicorn.run(asgi_app, host=HOST, port=PORT, workers=1)
