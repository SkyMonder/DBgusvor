import os
import json
from datetime import datetime
from urllib.parse import unquote
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DATA_FILE = "data.json"

# ─────────────────────────────────────────────
#  ПАРОЛИ ИЗ ENVIRONMENT VARIABLES
# ─────────────────────────────────────────────
DEFAULT_USERS = [
    {
        "id": 1,
        "name": "Арсений",
        "password": os.environ.get("PASSWORD_ARSENIY"),
        "lives": 3,
        "isAdmin": False,
        "avatar": "☕"
    },
    {
        "id": 2,
        "name": "Алекса",
        "password": os.environ.get("PASSWORD_ALEKSA"),
        "lives": 3,
        "isAdmin": False,
        "avatar": "☕"
    },
    {
        "id": 3,
        "name": "Даня",
        "password": os.environ.get("PASSWORD_DANYA"),
        "lives": 3,
        "isAdmin": False,
        "avatar": "☕"
    },
    {
        "id": 4,
        "name": "Петя",
        "password": os.environ.get("PASSWORD_PETYA"),
        "lives": 3,
        "isAdmin": False,
        "avatar": "☕"
    },
    {
        "id": 5,
        "name": "Тася",
        "password": os.environ.get("PASSWORD_TASYA"),
        "lives": 3,
        "isAdmin": True,
        "avatar": "☕"
    },
]

DEFAULT_NEWS = [
    {
        "id": 1,
        "title": "Добро пожаловать!",
        "content": "Это наша общая доска новостей. Здесь можно писать всё что угодно — анонсы, мемы, важные объявления. Редактировать может каждый!",
        "author": "Даня",
        "date": "2026-05-18T20:00:00"
    }
]


def load_data():
    if not os.path.exists(DATA_FILE):
        data = {
            "users": DEFAULT_USERS,
            "news": DEFAULT_NEWS,
            "nextNewsId": 2
        }
        save_data(data)
        return data
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────
#  РАЗДАЧА СТАТИКИ (фронтенд)
# ─────────────────────────────────────────────
@app.route("/")
def serve_index():
    return send_from_directory(".", "index.html")


@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(".", path)


# ─────────────────────────────────────────────
#  API: ЗДОРОВЬЕ
# ─────────────────────────────────────────────
@app.route("/ping")
def ping():
    return "pong"


# ─────────────────────────────────────────────
#  API: АВТОРИЗАЦИЯ
# ─────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    body = request.json
    name = body.get("name")
    password = body.get("password")
    data = load_data()
    user = next((u for u in data["users"] if u["name"] == name), None)
    if not user or user["password"] != password:
        return jsonify({"error": "Неверное имя или пароль"}), 401
    return jsonify({
        "name": user["name"],
        "avatar": user["avatar"],
        "isAdmin": user["isAdmin"],
        "lives": user["lives"]
    })


# ─────────────────────────────────────────────
#  API: ПОЛУЧИТЬ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ (без паролей)
# ─────────────────────────────────────────────
@app.route("/api/lives")
def get_lives():
    data = load_data()
    users = [{k: v for k, v in u.items() if k != "password"} for u in data["users"]]
    return jsonify(users)


# ─────────────────────────────────────────────
#  API: ИЗМЕНИТЬ ЖИЗНИ (только админ)
# ─────────────────────────────────────────────
@app.route("/api/lives/<name>", methods=["PATCH"])
def update_lives(name):
    raw_auth = request.headers.get("X-Auth-Name", "")
    auth_name = unquote(raw_auth) if raw_auth else ""
    if not auth_name:
        return jsonify({"error": "Не авторизован"}), 401

    data = load_data()
    admin = next((u for u in data["users"] if u["name"] == auth_name and u["isAdmin"]), None)
    if not admin:
        return jsonify({"error": "Только админ может менять жизни"}), 403

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

    save_data(data)
    return jsonify({"name": user["name"], "lives": user["lives"]})


# ─────────────────────────────────────────────
#  API: ПОЛУЧИТЬ ВСЕ НОВОСТИ
# ─────────────────────────────────────────────
@app.route("/api/news")
def get_news():
    data = load_data()
    news = sorted(data["news"], key=lambda n: n["date"], reverse=True)
    return jsonify(news)


# ─────────────────────────────────────────────
#  API: ДОБАВИТЬ НОВОСТЬ
# ─────────────────────────────────────────────
@app.route("/api/news", methods=["POST"])
def add_news():
    raw_auth = request.headers.get("X-Auth-Name", "")
    auth_name = unquote(raw_auth) if raw_auth else ""
    if not auth_name:
        return jsonify({"error": "Не авторизован"}), 401

    body = request.json
    title = body.get("title", "").strip()
    content = body.get("content", "").strip()
    if not title or not content:
        return jsonify({"error": "Заголовок и текст обязательны"}), 400

    data = load_data()
    new_id = data["nextNewsId"]
    news_item = {
        "id": new_id,
        "title": title,
        "content": content,
        "author": auth_name,
        "date": datetime.utcnow().isoformat()
    }
    data["news"].append(news_item)
    data["nextNewsId"] = new_id + 1
    save_data(data)
    return jsonify(news_item), 201


# ─────────────────────────────────────────────
#  API: РЕДАКТИРОВАТЬ НОВОСТЬ
# ─────────────────────────────────────────────
@app.route("/api/news/<int:news_id>", methods=["PUT"])
def edit_news(news_id):
    raw_auth = request.headers.get("X-Auth-Name", "")
    auth_name = unquote(raw_auth) if raw_auth else ""
    if not auth_name:
        return jsonify({"error": "Не авторизован"}), 401

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


# ─────────────────────────────────────────────
#  API: УДАЛИТЬ НОВОСТЬ
# ─────────────────────────────────────────────
@app.route("/api/news/<int:news_id>", methods=["DELETE"])
def delete_news(news_id):
    raw_auth = request.headers.get("X-Auth-Name", "")
    auth_name = unquote(raw_auth) if raw_auth else ""
    if not auth_name:
        return jsonify({"error": "Не авторизован"}), 401

    data = load_data()
    item = next((n for n in data["news"] if n["id"] == news_id), None)
    if not item:
        return jsonify({"error": "Новость не найдена"}), 404

    data["news"] = [n for n in data["news"] if n["id"] != news_id]
    save_data(data)
    return jsonify({"ok": True})


# ─────────────────────────────────────────────
#  ЗАПУСК
# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
