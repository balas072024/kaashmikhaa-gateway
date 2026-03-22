# -*- coding: utf-8 -*-
from flask import Flask, request, redirect, make_response, send_from_directory, jsonify, Response
from pathlib import Path
import requests as req
import secrets, jwt, time, os

app = Flask(__name__)
BASE = Path(__file__).parent
PRIVATE_PASSWORD = "arivu2026"
JWT_SECRET = "kaashmikhaa-jwt-2026"
COOKIE_NAME = "arivu_access"
COOKIE_DOMAIN = ".arivumaiyam.com"
VALID_TOKENS = set()

PORT_MAP = {
    "neuralbrain.": 8200, "chat.": 18789, "kaasai.": 3000,
    "valluvan.": 5000, "opsshiftpro.": 4000, "opswatch.": 3001,
    "vault.": 4100, "watch.": 9000,
}
PRIVATE_SUBS = {"neuralbrain.", "chat.", "watch."}

def make_token():
    t = secrets.token_urlsafe(32)
    VALID_TOKENS.add(t)
    return t

def is_authenticated():
    return request.cookies.get(COOKIE_NAME) in VALID_TOKENS

def get_host():
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or "arivumaiyam.com"
    return host.split(":")[0].lower()

def get_scheme():
    return request.headers.get("X-Forwarded-Proto", "https")

def _proxy(port, path):
    url = f"http://localhost:{port}/{path}"
    if request.query_string:
        url += "?" + request.query_string.decode()
    headers = {k: v for k, v in request.headers if k.lower() not in ("host","content-length","transfer-encoding")}
    try:
        r = req.request(method=request.method, url=url, headers=headers,
                        data=request.get_data(), stream=True, timeout=60, allow_redirects=False)
        excluded = {"transfer-encoding","content-encoding","content-length"}
        resp_headers = [(k,v) for k,v in r.headers.items() if k.lower() not in excluded]
        return Response(r.iter_content(chunk_size=8192), status=r.status_code, headers=resp_headers)
    except req.exceptions.ConnectionError:
        return jsonify({"error": f"Service on port {port} not running"}), 502

def _login_html(next_url="/", error=""):
    err = f'<div style="color:#ef4444;font-size:13px;margin-top:12px">{error}</div>' if error else ""
    return f'''<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private Access</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#04050a;color:#e8edf5;font-family:"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#080c14;border:1px solid #1a2235;border-radius:20px;padding:48px 40px;width:100%;max-width:380px;text-align:center}}
input{{width:100%;padding:12px 16px;background:#0d1220;border:1px solid #1a2235;border-radius:10px;color:#e8edf5;font-size:15px;outline:none;margin-bottom:12px}}
button{{width:100%;padding:13px;background:#0ea5e9;color:#000;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer}}</style>
</head><body><div class="card">
<div style="font-size:40px;margin-bottom:20px">⚡</div>
<div style="font-size:22px;font-weight:700;margin-bottom:6px">Private Access</div>
<div style="font-size:13px;color:#5a6a85;margin-bottom:32px">Restricted to Bala and family</div>
<form method="POST" action="/private-login">
<input type="hidden" name="next" value="{next_url}">
<input type="password" name="password" placeholder="Enter password" autofocus>
<button type="submit">Enter →</button></form>
{err}<div style="font-size:11px;color:#3d4f68;margin-top:20px">arivumaiyam.com · Kaashmikhaa Technologies</div>
</div></body></html>'''

@app.route("/private-login", methods=["GET","POST"])
def private_login():
    next_url = request.args.get("next") or request.form.get("next") or "/"
    if request.method == "POST":
        if request.form.get("password","").strip() == PRIVATE_PASSWORD:
            token = make_token()
            resp = make_response(redirect(f"{get_scheme()}://{get_host()}{next_url}", 302))
            resp.set_cookie(COOKIE_NAME, token, max_age=30*24*3600, secure=True, httponly=True, samesite="None", domain=COOKIE_DOMAIN)
            return resp
        return _login_html(next_url, "Wrong password. Try again.")
    return _login_html(next_url)

@app.route("/clear-auth")
def clear_auth():
    next_url = request.args.get("next", "/")
    resp = make_response(redirect(f"/private-login?next={next_url}"))
    for domain in [COOKIE_DOMAIN, "arivumaiyam.com"]:
        resp.delete_cookie(COOKIE_NAME, domain=domain, path="/")
    return resp

@app.route("/health")
def health():
    return jsonify({"service": "kaashmikhaa-gateway", "status": "healthy", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")})

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path=""):
    host = get_host()

    # Subdomain routing
    for subdomain, port in PORT_MAP.items():
        sub_clean = subdomain.rstrip(".")
        if host.startswith(subdomain) or host.startswith(sub_clean + ".") or host == sub_clean + ".arivumaiyam.com":
            if path in ("private-login", "clear-auth"):
                return private_login() if path == "private-login" else clear_auth()
            if subdomain in PRIVATE_SUBS and not is_authenticated():
                return redirect(f"/private-login?next=/{path}")
            return _proxy(port, path)

    # Family subdomain
    if host.startswith("family."):
        if path in ("private-login", "clear-auth"):
            return private_login() if path == "private-login" else clear_auth()
        if not is_authenticated():
            return redirect(f"/private-login?next=/{path}")
        tmpl = BASE / "templates" / "index.html"
        if tmpl.exists():
            return send_from_directory(str(tmpl.parent), tmpl.name)
        return jsonify({"service": "family-hub"})

    # Root domain - company page
    tmpl = BASE / "templates" / "company.html"
    if tmpl.exists():
        return send_from_directory(str(tmpl.parent), tmpl.name)
    return jsonify({"company": "Kaashmikhaa Technologies"})

if __name__ == "__main__":
    print("Kaashmikhaa Gateway starting on port 5013...")
    app.run(host="0.0.0.0", port=5013, debug=False)