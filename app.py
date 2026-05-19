import os
import json
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)

DATA_FILE = "data.json"
TOKEN_EXPIRY_HOURS = 1
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 10
MAX_FAILED_LOGINS = 5
BAN_TIME = 15 * 60

ALLOWED_ORIGINS = {
    "https://gusasya-vorobeychiky.onrender.com",
    "https://dbgusvor.onrender.com",
    "http://localhost:5000"
}

DEFAULT_USERS = [
    {"id": 2, "name": "Алекса",   "password": os.environ.get("PASSWORD_ALEKSA", "alexa2024"), "lives": 3, "isAdmin": False, "avatar": "☕"},
    {"id": 3, "name": "Даня",     "password": os.environ.get("PASSWORD_DANYA", "danya2024"), "lives": 3, "isAdmin": False, "avatar": "☕"},
    {"id": 4, "name": "Петя",     "password": os.environ.get("PASSWORD_PETYA", "petya2024"), "lives": 3, "isAdmin": False, "avatar": "☕"},
    {"id": 5, "name": "Тася",     "password": os.environ.get("PASSWORD_TASYA", "tasya2024"), "lives": 3, "isAdmin": True,  "avatar": "☕"},
]

DEFAULT_NEWS = [
    {"id": 1, "title": "Добро пожаловать!", "content": "Это наша общая доска новостей...", "author": "Тася", "date": "2024-01-15T12:00:00"}
]

active_tokens = {}
rate_limit_cache = {}
failed_logins = {}
banned_ips = {}

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return salt, h

def verify_password(password, salt, password_hash):
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest() == password_hash

def migrate_user_passwords(users):
    changed = False
    for user in users:
        if "password" in user and "password_hash" not in user:
            salt, p_hash = hash_password(user["password"])
            user["salt"] = salt
            user["password_hash"] = p_hash
            del user["password"]
            changed = True
    return changed

def load_data():
    if not os.path.exists(DATA_FILE):
        data = {"users": DEFAULT_USERS, "news": DEFAULT_NEWS, "nextNewsId": 2, "tokens": {}}
        migrate_user_passwords(data["users"])
        save_data(data)
        return data
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    if migrate_user_passwords(data["users"]):
        save_data(data)
    return data

def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_tokens():
    data = load_data()
    for token, info in data.get("tokens", {}).items():
        if "expires" in info:
            info["expires"] = datetime.fromisoformat(info["expires"])
        active_tokens[token] = info
    now = datetime.utcnow()
    expired = [t for t, v in active_tokens.items() if v["expires"] < now]
    for t in expired:
        del active_tokens[t]
    if expired:
        save_tokens()

def save_tokens():
    data = load_data()
    serializable = {}
    for token, info in active_tokens.items():
        serializable[token] = {
            "name": info["name"],
            "expires": info["expires"].isoformat(),
            "ip": info.get("ip"),
            "user_agent": info.get("user_agent")
        }
    data["tokens"] = serializable
    save_data(data)

def generate_token(name, ip, user_agent):
    token = secrets.token_hex(32)
    expires = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS)
    active_tokens[token] = {"name": name, "expires": expires, "ip": ip, "user_agent": user_agent}
    save_tokens()
    return token

def get_user_by_token(token):
    info = active_tokens.get(token)
    if not info or info["expires"] < datetime.utcnow():
        return None
    if get_real_ip() != info.get("ip") or request.headers.get("User-Agent") != info.get("user_agent"):
        del active_tokens[token]
        save_tokens()
        return None
    return info["name"]

def generate_csrf_token():
    return secrets.token_hex(32)

def get_real_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def check_origin():
    origin = request.headers.get("Origin") or request.headers.get("Referer")
    if not origin:
        return False
    origin = origin.rstrip("/")
    return origin in ALLOWED_ORIGINS

def rate_limit(endpoint):
    key = f"{get_real_ip()}:{endpoint}"
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    rate_limit_cache.setdefault(key, []).append(now)
    rate_limit_cache[key] = [t for t in rate_limit_cache[key] if t > window_start]
    return len(rate_limit_cache[key]) > RATE_LIMIT_MAX_REQUESTS

def is_banned():
    ip = get_real_ip()
    if ip in banned_ips:
        if time.time() - banned_ips[ip] < BAN_TIME:
            return True
        else:
            del banned_ips[ip]
    return False

def require_origin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_origin():
            return jsonify({"error": "Доступ запрещён (Origin)"}), 403
        return f(*args, **kwargs)
    return decorated

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_origin():
            return jsonify({"error": "Доступ запрещён (Origin)"}), 403
        token = request.cookies.get("auth_token")
        if not token:
            return jsonify({"error": "Требуется авторизация"}), 401
        username = get_user_by_token(token)
        if not username:
            return jsonify({"error": "Недействительный токен"}), 401
        request.current_user = username
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        username = getattr(request, 'current_user', None)
        if not username:
            return jsonify({"error": "Требуется авторизация"}), 401
        data = load_data()
        user = next((u for u in data["users"] if u["name"] == username), None)
        if not user or not user["isAdmin"]:
            return jsonify({"error": "Только админ"}), 403
        return f(*args, **kwargs)
    return decorated

def require_csrf(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ["POST", "PATCH", "PUT", "DELETE"]:
            header_token = request.headers.get("X-CSRF-Token")
            cookie_token = request.cookies.get("csrf_token")
            if not header_token or not cookie_token or header_token != cookie_token:
                return jsonify({"error": "Недействительный CSRF-токен"}), 403
        return f(*args, **kwargs)
    return decorated

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route("/")
def serve_index():
    return send_from_directory(".", "index.html")

@app.route("/index.html")
def serve_index_explicit():
    return send_from_directory(".", "index.html")

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route("/ping")
def ping():
    return "pong"

@app.route("/api/login", methods=["POST"])
@require_origin
def login():
    ip = get_real_ip()
    if is_banned():
        return jsonify({"error": "Заблокированы"}), 429
    if rate_limit("login"):
        return jsonify({"error": "Слишком много попыток"}), 429

    body = request.json
    name = body.get("name", "").strip()
    password = body.get("password", "")

    if not name or not password:
        return jsonify({"error": "Имя и пароль обязательны"}), 400

    data = load_data()
    user = next((u for u in data["users"] if u["name"] == name), None)
    if not user:
        return jsonify({"error": "Неверное имя или пароль"}), 401

    if "password_hash" in user:
        if not verify_password(password, user.get("salt", ""), user["password_hash"]):
            failed_logins.setdefault(ip, {"count": 0, "first_attempt": time.time()})
            failed_logins[ip]["count"] += 1
            if failed_logins[ip]["count"] >= MAX_FAILED_LOGINS:
                banned_ips[ip] = time.time()
                failed_logins.pop(ip, None)
                return jsonify({"error": "Слишком много неверных попыток. Заблокированы"}), 429
            return jsonify({"error": "Неверное имя или пароль"}), 401
    else:
        if user.get("password") != password:
            return jsonify({"error": "Неверное имя или пароль"}), 401

    failed_logins.pop(ip, None)
    token = generate_token(user["name"], ip, request.headers.get("User-Agent", ""))
    csrf = generate_csrf_token()

    resp = make_response(jsonify({
        "name": user["name"], "avatar": user["avatar"], "isAdmin": user["isAdmin"], "lives": user["lives"],
        "csrf_token": csrf
    }))
    resp.set_cookie("auth_token", value=token, max_age=TOKEN_EXPIRY_HOURS*3600,
                    httponly=True, secure=True, samesite="Strict", path="/")
    resp.set_cookie("csrf_token", value=csrf, max_age=TOKEN_EXPIRY_HOURS*3600,
                    httponly=False, secure=True, samesite="Strict", path="/")
    return resp

@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.cookies.get("auth_token")
    if token and token in active_tokens:
        del active_tokens[token]
        save_tokens()
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie("auth_token", "", expires=0, httponly=True, secure=True, samesite="Strict", path="/")
    resp.set_cookie("csrf_token", "", expires=0, httponly=False, secure=True, samesite="Strict", path="/")
    return resp

@app.route("/api/lives")
@require_auth
def get_lives():
    data = load_data()
    users = [{k: v for k, v in u.items() if k != "password"} for u in data["users"]]
    return jsonify(users)

@app.route("/api/lives/<name>", methods=["PATCH"])
@require_auth
@require_admin
@require_csrf
def update_lives(name):
    if rate_limit("lives_update"):
        return jsonify({"error": "Слишком много запросов"}), 429
    data = load_data()
    user = next((u for u in data["users"] if u["name"] == name), None)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    body = request.json
    if "lives" in body:
        lives = int(body["lives"])
        lives = max(0, min(99, lives))
        user["lives"] = lives
    elif "delta" in body:
        delta = int(body["delta"])
        user["lives"] = max(0, min(99, user["lives"] + delta))
    else:
        return jsonify({"error": "Укажите lives или delta"}), 400
    save_data(data)
    return jsonify({"name": user["name"], "lives": user["lives"]})

@app.route("/api/me")
@require_auth
def me():
    data = load_data()
    user = next((u for u in data["users"] if u["name"] == request.current_user), None)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    return jsonify({"name": user["name"], "avatar": user["avatar"], "isAdmin": user["isAdmin"], "lives": user["lives"]})

@app.route("/api/news")
@require_auth
def get_news():
    data = load_data()
    news = sorted(data["news"], key=lambda n: n["date"], reverse=True)
    return jsonify(news)

@app.route("/api/news", methods=["POST"])
@require_auth
@require_csrf
def add_news():
    if rate_limit("news_add"):
        return jsonify({"error": "Слишком часто"}), 429
    body = request.json
    title = body.get("title", "").strip()
    content = body.get("content", "").strip()
    if not title or not content:
        return jsonify({"error": "Заголовок и текст обязательны"}), 400
    data = load_data()
    new_id = data["nextNewsId"]
    news_item = {
        "id": new_id, "title": title, "content": content,
        "author": request.current_user, "date": datetime.utcnow().isoformat()
    }
    data["news"].append(news_item)
    data["nextNewsId"] = new_id + 1
    save_data(data)
    return jsonify(news_item), 201

@app.route("/api/news/<int:news_id>", methods=["PUT"])
@require_auth
@require_csrf
def edit_news(news_id):
    data = load_data()
    item = next((n for n in data["news"] if n["id"] == news_id), None)
    if not item:
        return jsonify({"error": "Новость не найдена"}), 404
    body = request.json
    title = body.get("title", "").strip()
    content = body.get("content", "").strip()
    if not title or not content:
        return jsonify({"error": "Заголовок и текст обязательны"}), 400
    item["title"] = title
    item["content"] = content
    item["date"] = datetime.utcnow().isoformat()
    save_data(data)
    return jsonify(item)

@app.route("/api/news/<int:news_id>", methods=["DELETE"])
@require_auth
@require_csrf
def delete_news(news_id):
    data = load_data()
    item = next((n for n in data["news"] if n["id"] == news_id), None)
    if not item:
        return jsonify({"error": "Новость не найдена"}), 404
    data["news"] = [n for n in data["news"] if n["id"] != news_id]
    save_data(data)
    return jsonify({"ok": True})

EMERGENCY_RESET_KEY = os.environ.get("EMERGENCY_RESET_KEY", "change-me-emergency")
@app.route("/emergency-reset")
def emergency_reset():
    if request.args.get("key") != EMERGENCY_RESET_KEY:
        return "denied", 403
    active_tokens.clear()
    data = load_data()
    data["tokens"] = {}
    save_data(data)
    return "All sessions destroyed.", 200

if __name__ == "__main__":
    load_tokens()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
