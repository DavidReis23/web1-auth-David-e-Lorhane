import os
import json
import base64
import jwt
from flask import request, session

JWT_SECRET = os.getenv("JWT_SECRET", "jwtsecret")


def load_users():
    with open(os.path.join(os.path.dirname(__file__), "users.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users):
    with open(os.path.join(os.path.dirname(__file__), "users.json"), "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def check_basic_auth(auth_header):
    """Valida credenciais do Basic Auth"""
    if not auth_header or not auth_header.startswith("Basic "):
        return None
    try:
        encoded = auth_header.split(" ")[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
        users = load_users()
        for u in users:
            if u["username"] == username and u["password"] == password:
                return u
        return None
    except Exception:
        return None


def get_current_user():
    """
    Tenta identificar usuário logado
    via Sessão, JWT ou Basic Auth
    """
    # Sessão
    if "user_id" in session:
        users = load_users()
        return next((u for u in users if u["id"] == session["user_id"]), None)

    # JWT
    token = request.cookies.get("jwt") or request.headers.get("Authorization")
    if token:
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return decoded
        except jwt.InvalidTokenError:
            return None

    # Basic Auth
    auth_header = request.headers.get("Authorization")
    user = check_basic_auth(auth_header)
    if user:
        return user

    return None



def get_user_by_id(user_id):
    users = load_users()
    return next((u for u in users if u["id"] == user_id), None)


def create_user(username, password, role="user"):
    users = load_users()
    new_id = max([u["id"] for u in users], default=0) + 1
    new_user = {
        "id": new_id,
        "username": username,
        "password": password,
        "role": role
    }
    users.append(new_user)
    save_users(users)
    return new_user


def update_user(user_id, username=None, password=None, role=None):
    users = load_users()
    for u in users:
        if u["id"] == user_id:
            if username:
                u["username"] = username
            if password:
                u["password"] = password
            if role:
                u["role"] = role
            save_users(users)
            return u
    return None


def delete_user(user_id):
    users = load_users()
    new_users = [u for u in users if u["id"] != user_id]
    if len(new_users) == len(users):
        return False
    save_users(new_users)
    return True
