import os
import json
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DATA_FILE = "data.json"

# ──────────────────────────────
#  ИНИЦИАЛИЗАЦИЯ ДАННЫХ
# ──────────────────────────────
DEFAULT_USERS = [
    {"id": 1, "name": "Арсений", "password": "ars2024", "lives": 3, "isAdmin": False, "avatar": "☕"},
    {"id": 2, "name": "Алекса",   "password": "alexa2024", "lives": 3, "isAdmin": False, "avatar": "☕"},
    {"id": 3, "name": "Даня",     "password": "danya2024", "lives": 3, "isAdmin": False, "avatar": "☕"},
    {"id": 4, "name": "Петя",     "password": "petya2024", "lives": 3, "isAdmin": False, "avatar": "☕"},
    {"id": 5, "name": "Тася",     "password": "tasya2024", "lives": 3, "isAdmin": True,  "avatar": "☕"},
]

DEFAULT_NEWS = [
    {
        "id": 1,
        "title": "Добро пожаловать!",
        "content": "Это наша общая доска новостей. Здесь можно писать всё что угодно — анонсы, мемы, важные объявления. Редактировать может каждый!",
        "author": "Даня",
        "date": "2026-05-18T19:00:00"
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


# ──────────────────────────────
#  API РОУТЫ
# ──────────────────────────────

# Здоровье (для cron-job)
@app.route("/ping")
def ping():
    return "pong"


# Авторизация
@app.route("/api/login", methods=["POST"])
def login():
    body = request.json
    name = body.get("name")
    password = body.get("password")
    data = load_data()
    user = next((u for u in data["users"] if u["name"] == name), None)
    if not user or user["password"] != password:
        return jsonify({"error": "Неверное имя или пароль"}), 401
    # Не возвращаем пароль
    return jsonify({
        "name": user["name"],
        "avatar": user["avatar"],
        "isAdmin": user["isAdmin"],
        "lives": user["lives"]
    })


# Получить список жизней (все пользователи, но без паролей)
@app.route("/api/lives")
def get_lives():
    data = load_data()
    users = [{k: v for k, v in u.items() if k != "password"} for u in data["users"]]
    return jsonify(users)


# Изменить жизни (только админ)
@app.route("/api/lives/<name>", methods=["PATCH"])
def update_lives(name):
    auth_name = request.headers.get("X-Auth-Name")
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


# Новости: получить все
@app.route("/api/news")
def get_news():
    data = load_data()
    # Сортируем от новых к старым
    news = sorted(data["news"], key=lambda n: n["date"], reverse=True)
    return jsonify(news)


# Добавить новость (любой авторизованный)
@app.route("/api/news", methods=["POST"])
def add_news():
    auth_name = request.headers.get("X-Auth-Name")
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


# Редактировать новость
@app.route("/api/news/<int:news_id>", methods=["PUT"])
def edit_news(news_id):
    auth_name = request.headers.get("X-Auth-Name")
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
    item["date"] = datetime.utcnow().isoformat()  # обновляем дату
    save_data(data)
    return jsonify(item)


# Удалить новость
@app.route("/api/news/<int:news_id>", methods=["DELETE"])
def delete_news(news_id):
    auth_name = request.headers.get("X-Auth-Name")
    if not auth_name:
        return jsonify({"error": "Не авторизован"}), 401

    data = load_data()
    item = next((n for n in data["news"] if n["id"] == news_id), None)
    if not item:
        return jsonify({"error": "Новость не найдена"}), 404

    data["news"] = [n for n in data["news"] if n["id"] != news_id]
    save_data(data)
    return jsonify({"ok": True})


# ──────────────────────────────
#  ЗАПУСК (локально или на Render)
# ──────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)