from enum import Enum

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    username: str
    email: EmailStr


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class UserPermissions(UserBase):
    permissions: list[str]


class UserCreate(UserBase):
    first_name: str
    last_name: str

    password: str


class UserStatus(Enum):
    PENDING = 1
    ACTIVE = 2
    DISABLED = 3
