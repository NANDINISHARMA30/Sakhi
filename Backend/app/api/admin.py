from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from starlette.requests import Request
import os
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "adminpass")

class AdminLoginRequest(BaseModel):
    email: str
    password: str

@router.post("/login")
def admin_login(payload: AdminLoginRequest):
    if payload.email == ADMIN_EMAIL and payload.password == ADMIN_PASSWORD:
        return {"message": "Admin login successful"}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials")
