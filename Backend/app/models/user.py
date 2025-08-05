from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr
    name: str

class UserCreate(UserBase):
    password: str
    age: Optional[int] = None
    contact_number: Optional[str] = None
    university_location: Optional[str] = None

class UserInDB(UserBase):
    id: str = Field(..., alias="_id")
    hashed_password: str
    is_active: bool = True
    is_verified: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        allow_population_by_field_name = True

class UserOut(UserBase):
    id: str
    is_verified: bool
    age: Optional[int] = None
    university_location: Optional[str] = None
