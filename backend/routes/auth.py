"""Authentication routes — register & login."""
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr

from database.database_manager import register_user, login_user, reset_password
from backend.auth_utils import create_access_token

router = APIRouter()


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str
    new_password: str


@router.post("/register")
def register(req: RegisterRequest):
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    success = register_user(req.username, req.email, req.password)
    if not success:
        raise HTTPException(status_code=409, detail="Email already registered")
    return {"message": "Account created successfully"}


@router.post("/login")
def login(req: LoginRequest):
    user = login_user(req.email, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": str(user[0]), "username": user[1], "email": user[2]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user[0], "username": user[1], "email": user[2]},
    }


@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    success, msg = reset_password(req.email, req.new_password)
    if not success:
        raise HTTPException(status_code=404, detail=msg)
    return {"message": msg}
