from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.user import UserBase, UserCreate, UserPermissions

router = APIRouter(prefix="/user", tags=["Create User"])


oauth_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def user_exists(
    username: str,
    session: Session,
) -> bool:
    query = select(User).where(User.username == username)

    row = session.execute(query).first()

    return row is not None


def user_table_is_empty(session: Session) -> bool:
    return user_exists("", session)


def user_create_superuser(user_dict: dict) -> User:
    return User(**user_dict, superuser=True)


def user_notify_admin(email: str, message=""):
    print(email, message)
    pass


def user_get(username: str, session: Session) -> User | None:
    query = select(User).where(User.username == username)

    row = session.execute(query).first()

    if not row:
        return None

    user = User(**row._mapping)

    return user


def user_authenticate(
    username: str,
    password: str,
    session: Session,
) -> User | None:
    user = user_get(username, session)

    # !(a && b) === !a || !b
    if not (user and pwd_context.verify(password, user.password)):
        return None

    return user


def user_get_current(
    token: Annotated[str, Depends(oauth_scheme)],
    session: Session,
):
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        username = payload.get("username")
        if not username:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "Could not validate credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = user_get(username, session)
    if not user or user.deleted:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

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


@router.post("/create", response_model=UserBase)
async def user_create(
    request: UserCreate,
    bg_tasks: BackgroundTasks,
    session: Session,
    _: Annotated[
        bool,
        Depends(PermissionChecker(permissions=["create_user"])),
    ],
):
    """
    Default endpoint of the "/create" route.

    :param request: A request body containing all information
                    necessary to create a user in the database.
    :type request: <app.schemas.UserCreate>
    """
    if user_table_is_empty(session):
        # check if we should create the user as pending and send the email for
        # an admin to activate or not even create the user and just notify
        super_user = user_create_superuser(request.model_dump())

        session.add(super_user)
        session.commit()
        bg_tasks.add_task(
            user_notify_admin,
            email="",
            message="",
        )

    if user_exists(request.username, session):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Username {request.username} is already registered.",
        )

    user = User(
        **request.model_dump(),
        password=pwd_context.hash(request.password),
        status=2,
    )

    session.add(user)
    session.commit()

    return UserBase(username=user.username, email=user.email)
