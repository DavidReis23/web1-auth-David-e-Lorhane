import os, json, base64, jwt
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response, g
from dotenv import load_dotenv
from helper import load_users, save_users, get_current_user

# Carrega variáveis do .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")
JWT_SECRET = os.getenv("JWT_SECRET", "jwtsecret")

# --- Função para carregar usuários do arquivo JSON ---
def load_users():
    with open(os.path.join(os.path.dirname(__file__), "users.json"), "r", encoding="utf-8") as f:
        return json.load(f)

# --- Autenticação via Basic Auth ---
def check_basic_auth(auth_header):
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

# --- Decorador para proteger rotas ---
def login_required(method="session"):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            g.user = None
            g.token = None

            def check_session():
                if "user_id" in session:
                    users = load_users()
                    return next((u for u in users if u["id"] == session["user_id"]), None)
                return None

            def check_jwt():
                token = request.cookies.get("jwt") or request.headers.get("Authorization")
                if not token:
                    return None, None
                try:
                    if token.startswith("Bearer "):
                        token = token.split(" ")[1]
                    decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
                    return decoded, token
                except jwt.InvalidTokenError:
                    return None, None

            def check_basic():
                auth_header = request.headers.get("Authorization")
                return check_basic_auth(auth_header)

            if method == "session":
                g.user = check_session()
                if not g.user:
                    return redirect(url_for("login"))

            elif method == "jwt":
                g.user, g.token = check_jwt()
                if not g.user:
                    return jsonify({"error": "Token inválido ou ausente"}), 401

            elif method == "basic":
                g.user = check_basic()
                if not g.user:
                    return make_response("Não autorizado", 401, {"WWW-Authenticate": "Basic realm='Login'"})

            elif method == "any":
                # tenta na ordem: session > jwt > basic
                g.user = check_session()
                if g.user:
                    return f(*args, **kwargs)

                g.user, g.token = check_jwt()
                if g.user:
                    return f(*args, **kwargs)

                g.user = check_basic()
                if g.user:
                    return f(*args, **kwargs)

                return redirect(url_for("login"))

            return f(*args, **kwargs)
        return wrapper
    return decorator


# --- Rotas ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        method = request.form.get("method")  # session / jwt / basic

        users = load_users()
        user = next((u for u in users if u["username"] == username and u["password"] == password), None)

        if not user:
            return render_template("login.html", error="Credenciais inválidas")

        if method == "session":
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        elif method == "jwt":
            token = jwt.encode({"id": user["id"], "username": user["username"], "role": user["role"]}, JWT_SECRET, algorithm="HS256")
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("jwt", token, httponly=True)
            return resp

        elif method == "basic":
            return jsonify({"message": "Use Basic Auth no header para acessar rotas protegidas"})

    return render_template("login.html")

@app.route("/admin/users")
def admin_users():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return "Acesso negado", 403
    users = load_users()
    return render_template("admin_users.html", users=users)

@app.route("/admin/add", methods=["POST"])
def add_user():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return "Acesso negado", 403

    username = request.form.get("username")
    password = request.form.get("password")
    role = request.form.get("role", "user")

    users = load_users()
    new_id = max(u["id"] for u in users) + 1 if users else 1
    users.append({"id": new_id, "username": username, "password": password, "role": role})
    save_users(users)
    return redirect(url_for("admin_users"))

@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    user = get_current_user()
    if not user or user["role"] != "admin":
        return "Acesso negado", 403

    users = load_users()
    users = [u for u in users if u["id"] != user_id]
    save_users(users)
    return redirect(url_for("admin_users"))

@app.route("/dashboard")
@login_required(method="any")  # aceita qualquer um dos 3
def dashboard():
    return render_template("protected.html", user=g.user, token=g.token)

@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("jwt")
    return resp

if __name__ == "__main__":
    app.run(debug=True)
