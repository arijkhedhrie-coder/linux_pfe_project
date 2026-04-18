from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from jose import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import json, os

router = APIRouter()

# ── Config JWT ─────────────────────────────────────────────
SECRET_KEY = "security-dashboard-secret-key-2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ── Stockage utilisateurs (fichier JSON local) ─────────────
USERS_FILE = "users.json"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# ── Modèles ────────────────────────────────────────────────
class SignupRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str

# ── POST /auth/signup ──────────────────────────────────────
@router.post("/auth/signup", status_code=201)
def signup(data: SignupRequest):
    users = load_users()

    if data.username in users:
        raise HTTPException(
            status_code=400,
            detail="Nom d'utilisateur déjà utilisé."
        )

    users[data.username] = {
        "username": data.username,
        "email": data.email,
        "hashed_password": pwd_context.hash(data.password),
        "created_at": datetime.utcnow().isoformat()
    }
    save_users(users)
    return {"message": "Compte créé avec succès.", "username": data.username}

# ── POST /auth/login ───────────────────────────────────────
@router.post("/auth/login", response_model=TokenResponse)
def login(credentials: LoginRequest):
    users = load_users()
    user = users.get(credentials.username)

    if not user or not pwd_context.verify(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Identifiants invalides. Accès refusé."
        )

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode(
        {"sub": credentials.username, "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": credentials.username
    }