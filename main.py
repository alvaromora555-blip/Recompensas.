import os, hashlib, secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import jwt
import psycopg
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]

app = FastAPI(title="Recompensa API", version="3.0.0")
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

def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Falta el token Bearer")
    try:
        uid = int(jwt.decode(authorization[7:], JWT_SECRET,
                             algorithms=["HS256"])["sub"])
    except Exception:
        raise HTTPException(401, "Token inválido o expirado")
    with db() as conn:
        user = conn.execute(
            "SELECT id,email,name,created_at FROM users WHERE id=%s", (uid,)
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
          created_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
        c.execute("""CREATE TABLE IF NOT EXISTS balances (
          user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          amount NUMERIC(12,2) NOT NULL DEFAULT 0,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
        c.execute("""CREATE TABLE IF NOT EXISTS transactions (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT REFERENCES users(id) ON DELETE CASCADE NOT NULL,
          type TEXT NOT NULL CHECK(type IN ('earning','withdrawal')),
          amount NUMERIC(12,2) NOT NULL CHECK(amount > 0),
          status TEXT NOT NULL DEFAULT 'completed',
          description TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
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

@app.post("/earn/demo")
def earn_demo(user=Depends(current_user)):
    # TEST ONLY: simulates a $1 MXN reward.
    amount = Decimal("1.00")
    with db() as c:
        c.execute(
            "UPDATE balances SET amount=amount+%s,updated_at=now() WHERE user_id=%s",
            (amount, user["id"])
        )
        c.execute(
            """INSERT INTO transactions(user_id,type,amount,description)
               VALUES(%s,'earning',%s,'Recompensa de prueba')""",
            (user["id"], amount)
        )
        c.commit()
    return {"ok":True, "added":amount}

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
