import os
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_file, redirect
import json
import re
import secrets
import time
from collections import defaultdict
from urllib.request import Request, urlopen
from urllib.parse import urlencode
import threading
from dotenv import load_dotenv
from scrape import scheduler_loop

load_dotenv()

app = Flask(__name__)

_file_lock = threading.Lock()

BASE = Path(__file__).parent

_oauth_states = set()

def _update_json(path, fn):
    """Atomically read JSON, apply fn(data), and write back."""
    with _file_lock:
        raw = path.read_bytes()
        data = json.loads(raw) if raw.strip() else ({} if path.name == "tokens.json" else [])
        result = fn(data)
        path.write_text(json.dumps(result, indent=2), "utf-8")
        return result

def _read_json(path):
    """Thread-safe JSON read."""
    with _file_lock:
        raw = path.read_bytes()
        return json.loads(raw) if raw.strip() else ({} if path.name == "tokens.json" else [])

_ratelimits = defaultdict(list)

def _check_limit(key, max_req, window):
    now = time.time()
    cutoff = now - window
    _ratelimits[key] = [t for t in _ratelimits[key] if t > cutoff]
    if len(_ratelimits[key]) >= max_req:
        return False
    _ratelimits[key].append(now)
    return True

def _rl(limit, window=60):
    return _check_limit(request.remote_addr + "|" + request.path, limit, window)

FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5500/frontend")
HCA_CLIENT_ID = os.environ.get("HCA_CLIENT_ID", "")
HCA_CLIENT_SECRET = os.environ.get("HCA_CLIENT_SECRET", "")
HCA_REDIRECT_URI = os.environ.get(
    "HCA_REDIRECT_URI", "http://localhost:6767/api/auth/callback"
)

REPORTS_FILE = BASE / "data" / "reports.json"
COMMENTS_FILE = BASE / "data" / "comments.json"
COMMENT_REPORTS_FILE = BASE / "data" / "comment-reports.json"
TOKENS_FILE = BASE / "data" / "tokens.json"

(BASE / "data").mkdir(parents=True, exist_ok=True)
for f in [REPORTS_FILE, COMMENTS_FILE, COMMENT_REPORTS_FILE]:
    if not f.exists() or f.stat().st_size == 0:
        f.write_text("[]", "utf-8")
if not TOKENS_FILE.exists() or TOKENS_FILE.stat().st_size == 0:
    TOKENS_FILE.write_text("{}", "utf-8")

BAD_WORDS = [
    "shit", "ass", "bitch", "crap", "dick", "bastard",
    "piss", "slut", "whore", "cock", "cunt", "douche", "fag", "nigger",
    "nigga", "chink", "spic", "kike", "gook", "tranny", "retard",
    "motherfucker", "twat", "wanker", "porn", "sex",
]

def contains_bad_words(text):
    return any(w in text.lower() for w in BAD_WORDS)

def sanitize(text):
    result = text
    for word in BAD_WORDS:
        result = re.sub(re.escape(word), "*" * len(word), result, flags=re.IGNORECASE)
    return result

def get_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    try:
        tokens = _read_json(TOKENS_FILE)
    except (json.JSONDecodeError, OSError):
        tokens = {}
    return tokens.get(token)

@app.after_request
def cors(resp):
    origin = request.headers.get("Origin", "")
    allowed = FRONTEND_ORIGIN
    if origin and (origin == allowed or "localhost" in origin or "127.0.0.1" in origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    if request.method == "OPTIONS":
        return resp
    return resp

@app.route("/projects.json")
def data():
    resp = send_file(BASE / "data" / "projects.json", mimetype="application/json")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/api/report", methods=["POST", "OPTIONS"])
def report():
    if request.method == "OPTIONS":
        return app.make_default_options_response()
    body = request.get_json(silent=True)
    if not body or not body.get("projectId") or not body.get("reason"):
        return jsonify({"ok": False, "error": "projectId and reason are required"}), 400
    details = (body.get("details") or "").strip()
    contact = (body.get("contact") or "").strip()
    if len(details) > 2000:
        return jsonify({"ok": False, "error": "Details too long (max 2000 chars)"}), 400
    if len(contact) > 200:
        return jsonify({"ok": False, "error": "Contact too long (max 200 chars)"}), 400
    if not _rl(2, 10) or not _rl(10, 60):
        return jsonify({"ok": False, "error": "Too many reports. Slow down."}), 429
    _update_json(REPORTS_FILE, lambda r: r + [{
        "projectId": body["projectId"],
        "reason": body["reason"],
        "details": details,
        "contact": contact,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }])
    return jsonify({"ok": True})

@app.route("/api/auth/login")
def auth_login():
    if not HCA_CLIENT_ID:
        return jsonify({"ok": False, "error": "HCA not configured"}), 503
    if not _rl(3, 10) or not _rl(20, 60):
        return jsonify({"ok": False, "error": "Too many login attempts. Slow down."}), 429
    state = secrets.token_urlsafe(32)
    _oauth_states.add(state)
    params = {
        "client_id": HCA_CLIENT_ID,
        "redirect_uri": HCA_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile email slack_id name",
        "state": state,
    }
    return redirect(f"https://auth.hackclub.com/oauth/authorize?{urlencode(params)}")

@app.route("/api/auth/callback")
def auth_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return "Missing code parameter", 400
    if not state or state not in _oauth_states:
        return "Invalid state parameter", 400
    if not _rl(3, 10) or not _rl(20, 60):
        return "Too many auth attempts. Slow down.", 429
    _oauth_states.discard(state)
    token_data = {
        "client_id": HCA_CLIENT_ID,
        "client_secret": HCA_CLIENT_SECRET,
        "redirect_uri": HCA_REDIRECT_URI,
        "code": code,
        "grant_type": "authorization_code",
    }
    try:
        req = Request(
            "https://auth.hackclub.com/oauth/token",
            data=urlencode(token_data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urlopen(req) as resp:
            raw = resp.read()
            print("TOKEN RESPONSE:", raw[:500])
            token_resp = json.loads(raw)
        access_token = token_resp.get("access_token")
        if not access_token:
            return "Failed to get access token", 400
        user_req = Request(
            "https://auth.hackclub.com/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        with urlopen(user_req) as resp:
            raw = resp.read()
            print("USERINFO RESPONSE:", raw[:500])
            user_data = json.loads(raw)
        identity_req = Request(
            "https://auth.hackclub.com/api/v1/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        with urlopen(identity_req) as resp:
            raw = resp.read()
            print("IDENTITY RESPONSE:", raw[:500])
            identity_data = json.loads(raw)
        slack_id = identity_data.get("identity", {}).get("slack_id", "")
        display_name = ""
        if slack_id:
            try:
                cachet_req = Request(f"https://cachet.dunkirk.sh/users/{slack_id}")
                with urlopen(cachet_req) as resp:
                    cachet_data = json.loads(resp.read())
                    display_name = cachet_data.get("displayName", "")
            except Exception:
                pass
        user_info = {
            "slack_id": slack_id,
            "name": display_name or user_data.get("nickname") or user_data.get("name") or (user_data.get("email") or "Hacker").split("@")[0],
            "email": user_data.get("email", ""),
        }
        session_token = secrets.token_urlsafe(32)
        _update_json(TOKENS_FILE, lambda t: {**t, session_token: user_info})
    except Exception as e:
        return f"Auth failed: {e}", 400
    return redirect(f"{FRONTEND_ORIGIN}#token={session_token}")

@app.route("/api/auth/me")
def auth_me():
    if not _rl(10, 10) or not _rl(60, 60):
        return jsonify({"ok": False, "error": "Too many requests."}), 429
    user = get_user()
    return jsonify({"user": user or None})

@app.route("/api/auth/logout")
def auth_logout():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        _update_json(TOKENS_FILE, lambda t: {k: v for k, v in t.items() if k != token})
    return jsonify({"ok": True})

@app.route("/api/comments/<int:project_id>")
def get_comments(project_id):
    comments = _read_json(COMMENTS_FILE)
    project_comments = [c for c in comments if c["projectId"] == project_id]
    return jsonify(project_comments)

@app.route("/api/comments", methods=["POST", "OPTIONS"])
def add_comment():
    if request.method == "OPTIONS":
        return app.make_default_options_response()
    user = get_user()
    if not user:
        return jsonify({"ok": False, "error": "You must be signed in to comment"}), 401
    body = request.get_json(silent=True)
    if not body or not body.get("projectId"):
        return jsonify({"ok": False, "error": "projectId is required"}), 400
    if not _rl(3, 10) or not _rl(15, 60):
        return jsonify({"ok": False, "error": "Too many comments. Slow down."}), 429
    text = (body.get("text") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "Comment cannot be empty"}), 400
    if len(text) > 1000:
        return jsonify({"ok": False, "error": "Comment too long (max 1000 chars)"}), 400
    if contains_bad_words(text) or contains_bad_words(user.get("name", "")):
        return jsonify({"ok": False, "error": "Comment contains inappropriate language"}), 400
    parent_id = body.get("parentId")
    if parent_id is not None and (not isinstance(parent_id, int) or parent_id < 1):
        return jsonify({"ok": False, "error": "Invalid parentId"}), 400
    _update_json(COMMENTS_FILE, lambda c: c + [{
        "id": (max(cc["id"] for cc in c) if c else 0) + 1,
        "projectId": body["projectId"],
        "username": user["name"],
        "slack_id": user["slack_id"],
        "text": sanitize(text),
        "parentId": parent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }])
    return jsonify({"ok": True})

@app.route("/api/comment-report", methods=["POST", "OPTIONS"])
def report_comment():
    if request.method == "OPTIONS":
        return app.make_default_options_response()
    body = request.get_json(silent=True)
    if not body or not body.get("commentId") or not body.get("projectId"):
        return jsonify({"ok": False, "error": "commentId and projectId are required"}), 400
    if not _rl(2, 10) or not _rl(10, 60):
        return jsonify({"ok": False, "error": "Too many reports. Slow down."}), 429
    _update_json(COMMENT_REPORTS_FILE, lambda r: r + [{
        "commentId": body["commentId"],
        "projectId": body["projectId"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }])
    return jsonify({"ok": True})

# scrape every day :p
threading.Thread(target=scheduler_loop, daemon=True).start()

app.run(host="0.0.0.0", port=6767)
