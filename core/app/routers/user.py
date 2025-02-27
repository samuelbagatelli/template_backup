from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.user import UserCreate, UserPermissions
from app.settings.database import get_session
from app.utils.user import user_exists, user_get, user_table_is_empty

router = APIRouter(prefix="/user", tags=["Create User"])


oauth_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def user_authenticate(
    username: str,
    password: str,
    session: Session,
) -> User | None:
    """
    Check if an user with :username: and :password:
    exists in the database and verify hashed password.
    """
    user = user_get(username, session)

    # !(a && b) === !a || !b
    if not (user and pwd_context.verify(password, user.password)):
        return None

    return user


def user_get_current(
    token: Annotated[str, Depends(oauth_scheme)],
    session: Session = Depends(get_session),
):
    if user_table_is_empty(session):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "'core_user' table is empty, please contact admin",
        )

    credential_except = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        if not token:
            raise credential_except
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        username = payload.get("username")
        if not username:
            raise credential_except
    except JWTError:
        raise credential_except

    user = user_get(username, session)
    if not user or user.deleted:
        raise credential_except

    return user


class PermissionChecker:
    permissions: list[str]

    def __init__(self, permissions: list[str]) -> None:
        self.permissions = permissions

    def __call__(
        self,
        user: Annotated[
            UserPermissions,
            Depends(user_get_current),
        ],
    ) -> bool:
        if set(self.permissions).issubset(set(user.permissions)):
            return True
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "You don't have enough permissions.",
        )


@router.post("/create")
async def user_create(
    request: UserCreate,
    bg_tasks: BackgroundTasks,
    _: Annotated[
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
    if user_exists(request.username, session):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Username {request.username} is already registered.",
        )

    # user = User(
    #     **request.model_dump(),
    #     password=pwd_context.hash(request.password),
    #     status=2,
    # )
    #
    # session.add(user)
    # session.commit()

    # return UserBase(username=user.username, email=user.email)
    return
