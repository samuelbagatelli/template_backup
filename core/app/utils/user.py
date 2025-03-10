from datetime import datetime, timedelta, timezone
from typing import Annotated

from app.models.user import User
from app.schemas.user import UserBase, UserPermissions, UserStatus
from app.settings.database import get_session, settings
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth_scheme = OAuth2PasswordBearer(
    tokenUrl="user/login",
    auto_error=False,
)


def user_exists(
    user: UserBase,
    session: Session,
) -> bool:
    query = select(User).where(
        User.username == user.username or User.email == user.email
    )

    row = session.execute(query).first()

    return row is not None


def user_table_is_empty(session: Session = Depends(get_session)) -> bool:
    """
    Check if the 'core_user' table is empty on the database.
    """
    query = select(User.id).limit(1)

    row = session.execute(query).first()

    return row is None


def user_get(
    username: str,
    session: Session,
) -> User | None:
    """
    Search a user in the database with the given username.

    :raises HTTPException: If the user was not found.
    """
    query = select(User).where(User.username == username)

    info = session.execute(query).first()

    if not info:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")

    user = info._mapping["User"]

    return user


def user_auth_credentials(
    username: str,
    password: str,
    session: Session,
) -> User | None:
    """
    Function to validate user credentials and return a user
    if credentials are valid and exist in the database.

    If the credentials are not valid or don't
    exist in the database the function return None.
    """
    user = user_get(username, session=session)

    # !(a && b) === !a || !b
    if not (user and pwd_context.verify(password, user.password)):
        return None

    return user


def user_gen_access_token(data: dict) -> str:
    to_encd = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.jwt_expire_min,
    )

    to_encd.update({"exp": expire})

    return jwt.encode(
        to_encd,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def user_get_current(
    token: Annotated[str, Depends(oauth_scheme)],
    session: Session = Depends(get_session),
) -> User | None:
    """
    Function to extract the current user from the given Bearer Token.

    If the user table is empty in the database, the function returns None.

    Then, the function tryes to extract the username from the token.
    After this, if the username is extracted sucessfully
    and the user exists in the database, the user is returned.
    """
    if user_table_is_empty(session):
        return None

    credential_except = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        if not token:
            raise credential_except
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        username = payload.get("username")
        if not username:
            raise credential_except
    except JWTError:
        raise credential_except

    user = user_get(username, session)
    if not user or user.deleted:
        raise credential_except

    if user.status is UserStatus.DISABLED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This user is currently disabled.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def user_get_permissions(_: User) -> list[str]:
    return []


class PermissionChecker:
    """
    A class created to check if the user
    has the permission to execute some action.

    :attr permissions: A list of strings containing the
                       permissions necessary to perform some action.
    """

    permissions: list[str]

    def __init__(self, permissions: list[str]) -> None:
        self.permissions = permissions

    def user_is_allowed(self, permissions: list[str]) -> bool:
        return set(self.permissions).issubset(set(permissions))

    def __call__(
        self,
        user: Annotated[
            User,
            Depends(user_get_current),
        ],
    ) -> bool:
        if user is None:
            return False
        if self.user_is_allowed(user_get_permissions(user)) or user.superuser:
            return True
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "You don't have enough permissions.",
        )


def user_create_superuser(user_dict: dict, session: Session) -> User:
    """
    Function to create the superuser and commit it to the database.

    It receives a dictionary with all information
    necessary to create an instance of User.

    After the user is commited to the database,
    the function returns the instance.
    """
    user = User(
        **user_dict,
        superuser=True,
        status=UserStatus.ACTIVE,
    )

    session.add(user)
    session.commit()

    return user
