from typing import Annotated

from app.models.user import User
from app.schemas.user import Token, UserBase, UserCreate, UserLogin, UserStatus
from app.settings.database import get_session
from app.utils.user import (
    PermissionChecker,
    pwd_context,
    user_auth_credentials,
    user_create_superuser,
    user_exists,
    user_gen_access_token,
)
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

router = APIRouter(prefix="/user", tags=["Create User"])


@router.post("/login")
async def user_login(
    request: UserLogin,
    session: Session = Depends(get_session),
) -> Token:
    user = user_auth_credentials(
        request.username,
        request.password,
        session,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = user_gen_access_token(data={"username": user.username})

    return Token(access_token=access_token, token_type="bearer")


@router.post("/create")
async def user_create(
    request: UserCreate,
    superuser: Annotated[
        bool,
        Depends(PermissionChecker(permissions=["create_user"])),
    ],
    session: Session = Depends(get_session),
):
    """
    Default endpoint of the "/create" route.

    The route assumes someone is logged in
    and have the permission to create a user.

    :param request: A request body containing all information
                    necessary to create a user in the database.
    :type request: <app.schemas.UserCreate>
    """
    if user_exists(
        UserBase(
            username=request.username,
            email=request.email,
        ),
        session,
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Username or email is already registered.",
        )

    user_dict = request.model_dump()
    user_dict["password"] = pwd_context.hash(request.password)

    if not superuser:
        user = user_create_superuser(user_dict, session)
        return UserBase(username=user.username, email=user.email)

    user = User(
        **user_dict,
        status=UserStatus.ACTIVE.value,
    )

    session.add(user)
    session.commit()

    return UserBase(username=user.username, email=user.email)
