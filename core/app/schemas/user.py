from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    username: str
    email: EmailStr


class UserPermissions(UserBase):
    permissions: list[str]


class UserCreate(UserBase):
    first_name: str
    last_name: str

    password: str
