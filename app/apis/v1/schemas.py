from pydantic import BaseModel, EmailStr
from typing import Optional

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    phone_number: str
    password: str
    state: str
    county: str
    district: str
    school: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TeacherProfileCreate(BaseModel):
    name: str
    state: str
    county: str
    district: str
    school: str
    aboutMe: str
    wishlist: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[EmailStr] = None