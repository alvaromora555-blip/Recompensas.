import os, hashlib, secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import jwt
import psycopg
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]

from urllib.parse import urlparse

_db_info = urlparse(DATABASE_URL)
print("DATABASE USER:", _db_info.username)
print("DATABASE HOST:", _db_info.hostname)
print("DATABASE PORT:", _db_info.port)

app = FastAPI(title="Recompensa API", version="3.0.0")
security = HTTPBearer()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])

def db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"

def verify_password(password, stored):
    try:
        _, sh, dh = stored.split("$", 2)
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(sh),
                                n=2**14, r=8, p=1)
        return secrets.compare_digest(actual, bytes.fromhex(dh))
    except Exception:
        return False

def token_for(user_id):
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "iat": now,
               "exp": now + timedelta(days=30)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        uid = int(jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )["sub"])
    except Exception:
        raise HTTPException(401, "Token inválido o expirado")

    with db() as conn:
        user = conn.execute(
            "SELECT id,email,name,created_at FROM users WHERE id=%s",
            (uid,)
        ).fetchone()

    if not user:
        raise HTTPException(401, "Usuario no encontrado")

    return user

class RegisterIn(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=2, max_length=80)

class LoginIn(BaseModel):
    email: str
    password: str

class WithdrawIn(BaseModel):
    amount: Decimal = Field(gt=0)
  
@app.on_event("startup")
def startup():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
          id BIGSERIAL PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")
        c.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE
        """)
        c.execute("""CREATE TABLE IF NOT EXISTS balances (
          user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          amount NUMERIC(12,2) NOT NULL DEFAULT 0,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS transactions (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT REFERENCES users(id) ON DELETE CASCADE NOT NULL,
          type TEXT NOT NULL CHECK(type IN ('earning','withdrawal')),
          amount NUMERIC(12,2) NOT NULL CHECK(amount > 0),
          status TEXT NOT NULL DEFAULT 'completed',
          description TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS task_claims (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          task_id TEXT NOT NULL,
          amount NUMERIC(12,2) NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE(user_id, task_id)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS tasks (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          description TEXT NOT NULL,
          amount NUMERIC(12,2) NOT NULL CHECK(amount > 0),
          active BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")

        c.execute("""INSERT INTO tasks
          (id, title, description, amount)
          VALUES
            ('welcome', 'Recompensa de bienvenida',
             'Completa tu primera actividad.', 1.00),
            ('daily', 'Recompensa diaria',
             'Realiza la actividad diaria.', 0.50)
          ON CONFLICT (id) DO NOTHING
        """)
        c.commit()

@app.get("/")
def home():
    return {"app":"Recompensa","status":"online","version":"3.0.0"}

@app.get("/health")
def health():
    try:
        with db() as c:
            c.execute("SELECT 1")
        return {"ok":True,"database":"connected","version":"3.0.0"}
    except Exception as e:
        return {"ok":False,"database":"error","detail":str(e)}

@app.post("/auth/register")
def register(data: RegisterIn):
    email = data.email.strip().lower()
    if "@" not in email:
        raise HTTPException(400, "Correo inválido")
    with db() as c:
        try:
            user = c.execute(
                """INSERT INTO users(email,name,password_hash)
                   VALUES(%s,%s,%s)
                   RETURNING id,email,name,created_at""",
                (email, data.name.strip(), hash_password(data.password))
            ).fetchone()
            c.execute("INSERT INTO balances(user_id,amount) VALUES(%s,0)",
                      (user["id"],))
            c.commit()
        except psycopg.errors.UniqueViolation:
            c.rollback()
            raise HTTPException(409, "Ese correo ya está registrado")
    return {"user":user, "token":token_for(user["id"])}

@app.post("/auth/login")
def login(data: LoginIn):
    with db() as c:
        user = c.execute(
            "SELECT id,email,name,password_hash,created_at FROM users WHERE email=%s",
            (data.email.strip().lower(),)
        ).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(401, "Correo o contraseña incorrectos")
    user.pop("password_hash", None)
    return {"user":user, "token":token_for(user["id"])}

@app.get("/me")
def me(user=Depends(current_user)):
    return {"user":user}

@app.get("/balance")
def balance(user=Depends(current_user)):
    with db() as c:
        row = c.execute(
            "SELECT amount,updated_at FROM balances WHERE user_id=%s",
            (user["id"],)
        ).fetchone()
    return {"balance":row["amount"], "updated_at":row["updated_at"]}

@app.get("/transactions")
def transactions(user=Depends(current_user)):
    with db() as c:
        rows = c.execute(
            """SELECT id,type,amount,status,description,created_at
               FROM transactions
               WHERE user_id=%s
               ORDER BY id DESC LIMIT 100""",
            (user["id"],)
        ).fetchall()
    return {"transactions":rows}
@app.get("/tasks")
def tasks(user=Depends(current_user)):
    with db() as c:
        rows = c.execute(
            """
            SELECT
                t.id,
                t.title,
                t.description,
                t.amount,
                CASE
                    WHEN tc.task_id IS NOT NULL THEN true
                    ELSE false
                END AS claimed
            FROM tasks t
            LEFT JOIN task_claims tc
                ON tc.task_id = t.id
                AND tc.user_id = %s
            WHERE t.active = true
            ORDER BY t.id
            """,
            (user["id"],)
        ).fetchall()

    return {"tasks": rows}


@app.post("/tasks/{task_id}/complete")
def complete_task(task_id: str, user=Depends(current_user)):
    with db() as c:
        task = c.execute(
            """
            SELECT id, title, description, amount
            FROM tasks
            WHERE id = %s AND active = true
            """,
            (task_id,)
        ).fetchone()

        if not task:
            raise HTTPException(404, "Tarea no encontrada")

        try:
            # Una tarea solo puede pagarse una vez por usuario.
            c.execute(
                """
                INSERT INTO task_claims(user_id, task_id, amount)
                VALUES(%s, %s, %s)
                """,
                (user["id"], task["id"], task["amount"])
            )

            c.execute(
                """
                UPDATE balances
                SET amount = amount + %s,
                    updated_at = now()
                WHERE user_id = %s
                """,
                (task["amount"], user["id"])
            )

            c.execute(
                """
                INSERT INTO transactions(
                    user_id,
                    type,
                    amount,
                    status,
                    description
                )
                VALUES(%s, 'earning', %s, 'completed', %s)
                """,
                (
                    user["id"],
                    task["amount"],
                    task["description"]
                )
            )

            c.commit()

        except psycopg2.errors.UniqueViolation:
            c.rollback()
            raise HTTPException(
                409,
                "Esta tarea ya fue completada"
            )

    return {
        "ok": True,
        "task_id": task["id"],
        "added": task["amount"]
    }

@app.post("/withdraw")
def withdraw(data: WithdrawIn, user=Depends(current_user)):
    amount = data.amount.quantize(Decimal("0.01"))
    with db() as c:
        c.execute("SELECT pg_advisory_xact_lock(%s)", (user["id"],))
        row = c.execute(
            "SELECT amount FROM balances WHERE user_id=%s FOR UPDATE",
            (user["id"],)
        ).fetchone()
        if not row or row["amount"] < amount:
            raise HTTPException(400, "Saldo insuficiente")
        c.execute(
            "UPDATE balances SET amount=amount-%s,updated_at=now() WHERE user_id=%s",
            (amount, user["id"])
        )
        c.execute(
            """INSERT INTO transactions(user_id,type,amount,status,description)
               VALUES(%s,'withdrawal',%s,'pending','Solicitud de retiro')""",
            (user["id"], amount)
        )
        c.commit()
    return {"ok":True, "status":"pending", "amount":amount}
  
  def require_admin(user=Depends(current_user)):
    with db() as c:
        admin = c.execute(
            "SELECT is_admin FROM users WHERE id=%s",
            (user["id"],)
        ).fetchone()

    if not admin or not admin["is_admin"]:
        raise HTTPException(403, "Acceso solo para administradores")

    return user


@app.get("/admin/withdrawals")
def admin_withdrawals(user=Depends(require_admin)):
    with db() as c:
        rows = c.execute("""
            SELECT
                t.id,
                t.user_id,
                u.email,
                u.name,
                t.amount,
                t.status,
                t.description,
                t.created_at
            FROM transactions t
            JOIN users u ON u.id = t.user_id
            WHERE t.type = 'withdrawal'
            ORDER BY t.created_at DESC
        """).fetchall()

    return {"withdrawals": rows}


@app.post("/admin/withdrawals/{transaction_id}/approve")
def approve_withdrawal(
    transaction_id: int,
    user=Depends(require_admin)
):
    with db() as c:
        row = c.execute("""
            SELECT id, user_id, amount, status
            FROM transactions
            WHERE id=%s
              AND type='withdrawal'
            FOR UPDATE
        """, (transaction_id,)).fetchone()

        if not row:
            raise HTTPException(404, "Retiro no encontrado")

        if row["status"] != "pending":
            raise HTTPException(
                409,
                "Este retiro ya fue procesado"
            )

        c.execute("""
            UPDATE transactions
            SET status='completed',
                description='Retiro aprobado por administrador'
            WHERE id=%s
        """, (transaction_id,))

        c.commit()

    return {
        "ok": True,
        "status": "completed",
        "transaction_id": transaction_id
    }


@app.post("/admin/withdrawals/{transaction_id}/reject")
def reject_withdrawal(
    transaction_id: int,
    user=Depends(require_admin)
):
    with db() as c:
        row = c.execute("""
            SELECT id, user_id, amount, status
            FROM transactions
            WHERE id=%s
              AND type='withdrawal'
            FOR UPDATE
        """, (transaction_id,)).fetchone()

        if not row:
            raise HTTPException(404, "Retiro no encontrado")

        if row["status"] != "pending":
            raise HTTPException(
                409,
                "Este retiro ya fue procesado"
            )

        # Devolver el dinero al usuario
        c.execute("""
            UPDATE balances
            SET amount = amount + %s,
                updated_at = now()
            WHERE user_id=%s
        """, (row["amount"], row["user_id"]))

        # Marcar el retiro como rechazado
        c.execute("""
            UPDATE transactions
            SET status='rejected',
                description='Retiro rechazado por administrador'
            WHERE id=%s
        """, (transaction_id,))

        c.commit()

    return {
        "ok": True,
        "status": "rejected",
        "refunded": row["amount"],
        "transaction_id": transaction_id
    }
