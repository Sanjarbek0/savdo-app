import sqlite3
import os
from datetime import datetime, timedelta
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# =====================================================
# CONFIG
# =====================================================
SECRET_KEY = os.getenv("SECRET_KEY", "savdo-uz-secret-key-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
DB_PATH = os.getenv("DB_PATH", "savdo.db")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

app = FastAPI(title="savdo.uz API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================
# DATABASE
# =====================================================
def get_db_path():
    return DB_PATH


@contextmanager
def get_db():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Xodim',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                category TEXT NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('KIRIM', 'CHIQIM')),
                amount INTEGER NOT NULL CHECK(amount > 0),
                user_login TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Default admin user
        existing = conn.execute("SELECT id FROM users WHERE login = 'admin'").fetchone()
        if not existing:
            hashed = pwd_context.hash("admin123")
            conn.execute(
                "INSERT INTO users (login, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hashed, "Admin"),
            )

        # Default categories
        for cat in ["Marojniy", "Batut", "Popcorn"]:
            existing = conn.execute("SELECT id FROM categories WHERE name = ?", (cat,)).fetchone()
            if not existing:
                conn.execute("INSERT INTO categories (name) VALUES (?)", (cat,))


# =====================================================
# MODELS
# =====================================================
class LoginRequest(BaseModel):
    login: str
    password: str


class CategoryCreate(BaseModel):
    name: str


class TransactionCreate(BaseModel):
    category: str
    type: str
    amount: int


class UserCreate(BaseModel):
    login: str
    password: str
    role: str = "Xodim"


class PasswordUpdate(BaseModel):
    old_password: str
    new_password: str


# =====================================================
# AUTH
# =====================================================
def create_token(login: str, role: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    return jwt.encode({"sub": login, "role": role, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Token kerak")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        login = payload.get("sub")
        role = payload.get("role")
        if not login:
            raise HTTPException(status_code=401, detail="Noto'g'ri token")
        return {"login": login, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token muddati tugagan yoki noto'g'ri")


# =====================================================
# API ENDPOINTS
# =====================================================

# --- Auth ---
@app.post("/api/login")
def login(req: LoginRequest):
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE login = ?", (req.login,)).fetchone()
        if not user or not pwd_context.verify(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Login yoki parol xato!")
        token = create_token(user["login"], user["role"])
        return {"token": token, "login": user["login"], "role": user["role"]}


# --- Categories ---
@app.get("/api/categories")
def list_categories(user=Depends(get_current_user)):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM categories ORDER BY id").fetchall()
        return [{"id": r["id"], "name": r["name"]} for r in rows]


@app.post("/api/categories")
def add_category(cat: CategoryCreate, user=Depends(get_current_user)):
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM categories WHERE name = ?", (cat.name,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Bunday bo'lim mavjud!")
        conn.execute("INSERT INTO categories (name) VALUES (?)", (cat.name,))
        return {"ok": True}


@app.delete("/api/categories/{cat_id}")
def delete_category(cat_id: int, user=Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("DELETE FROM categories WHERE id = ?", (cat_id,))
        return {"ok": True}


# --- Transactions ---
@app.get("/api/transactions")
def list_transactions(user=Depends(get_current_user)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM transactions ORDER BY id DESC"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "date": r["date"],
                "cat": r["category"],
                "type": r["type"],
                "amount": r["amount"],
                "user": r["user_login"],
            }
            for r in rows
        ]


@app.post("/api/transactions")
def add_transaction(t: TransactionCreate, user=Depends(get_current_user)):
    if t.type not in ("KIRIM", "CHIQIM"):
        raise HTTPException(status_code=400, detail="Type must be KIRIM or CHIQIM")
    if t.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO transactions (date, category, type, amount, user_login) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d"), t.category, t.type, t.amount, user["login"]),
        )
        return {"ok": True}


@app.delete("/api/transactions/{trans_id}")
def delete_transaction(trans_id: int, user=Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("DELETE FROM transactions WHERE id = ?", (trans_id,))
        return {"ok": True}


# --- Users ---
@app.get("/api/users")
def list_users(user=Depends(get_current_user)):
    with get_db() as conn:
        rows = conn.execute("SELECT id, login, role, created_at FROM users ORDER BY id").fetchall()
        return [{"id": r["id"], "login": r["login"], "role": r["role"]} for r in rows]


@app.post("/api/users")
def add_user(u: UserCreate, user=Depends(get_current_user)):
    if user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Faqat admin foydalanuvchi qo'sha oladi")
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE login = ?", (u.login,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Bu login band!")
        hashed = pwd_context.hash(u.password)
        conn.execute(
            "INSERT INTO users (login, password_hash, role) VALUES (?, ?, ?)",
            (u.login, hashed, u.role),
        )
        return {"ok": True}


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, user=Depends(get_current_user)):
    if user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Faqat admin o'chira oladi")
    with get_db() as conn:
        target = conn.execute("SELECT login FROM users WHERE id = ?", (user_id,)).fetchone()
        if target and target["login"] == user["login"]:
            raise HTTPException(status_code=400, detail="O'zingizni o'chira olmaysiz!")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return {"ok": True}


# --- Profile ---
@app.put("/api/profile/password")
def update_password(req: PasswordUpdate, user=Depends(get_current_user)):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE login = ?", (user["login"],)).fetchone()
        if not row or not pwd_context.verify(req.old_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Eski parol noto'g'ri!")
        hashed = pwd_context.hash(req.new_password)
        conn.execute("UPDATE users SET password_hash = ? WHERE login = ?", (hashed, user["login"]))
        return {"ok": True}


# --- Dashboard stats ---
@app.get("/api/dashboard")
def dashboard_stats(date_from: str = "", date_to: str = "", user=Depends(get_current_user)):
    with get_db() as conn:
        query = "SELECT * FROM transactions WHERE 1=1"
        params = []
        if date_from:
            query += " AND date >= ?"
            params.append(date_from)
        if date_to:
            query += " AND date <= ?"
            params.append(date_to)

        rows = conn.execute(query, params).fetchall()

        total_in = sum(r["amount"] for r in rows if r["type"] == "KIRIM")
        total_out = sum(r["amount"] for r in rows if r["type"] == "CHIQIM")
        profit = total_in - total_out
        count = len(rows)

        # Category breakdown
        cat_stats = {}
        for r in rows:
            cat = r["category"]
            if cat not in cat_stats:
                cat_stats[cat] = {"kirim": 0, "chiqim": 0}
            if r["type"] == "KIRIM":
                cat_stats[cat]["kirim"] += r["amount"]
            else:
                cat_stats[cat]["chiqim"] += r["amount"]

        # Daily breakdown for charts
        daily = {}
        for r in rows:
            d = r["date"]
            if d not in daily:
                daily[d] = {"kirim": 0, "chiqim": 0}
            if r["type"] == "KIRIM":
                daily[d]["kirim"] += r["amount"]
            else:
                daily[d]["chiqim"] += r["amount"]

        return {
            "total_in": total_in,
            "total_out": total_out,
            "profit": profit,
            "count": count,
            "categories": cat_stats,
            "daily": daily,
        }


# --- Serve frontend ---
@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>savdo.uz</h1><p>Frontend topilmadi</p>")


# =====================================================
# STARTUP
# =====================================================
@app.on_event("startup")
def startup():
    init_db()
