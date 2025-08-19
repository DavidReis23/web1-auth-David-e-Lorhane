# Autenticação + Gerenciamento de Usuários (Flask)

## Visão Geral
Sistema Flask com:
- Login por Sessão, JWT e Basic Auth.
- Gerenciamento de usuários via arquivo `src/users.json`.
- Páginas protegidas e controle de acesso por role.
- Logs de DEBUG (ativados por `LOG_LEVEL=DEBUG`) para tentativas/resultado de login, emissão de JWT (payload sem segredo) e acessos a rotas protegidas.

## Como Executar
```bash
git clone <repo-url>
cd web1-auth-<seunome>
python -m venv venv
# Linux/Mac
source venv/bin/activate
# Windows
# venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env
# edite .env e defina seus valores (principalmente JWT_SECRET e SECRET_KEY_SESSION)

flask run
