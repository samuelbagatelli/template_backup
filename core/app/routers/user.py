from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy.util import NoneType

from app.models.user import User
from app.schemas.user import UserBase, UserCreate, UserPermissions
from app.settings.database import get_session
from app.utils.user import user_exists, user_get, user_table_is_empty

JWT_SECRET = "secret"  # change this to something safer and not commited on git
JWT_ALGORITHM = "HS256"

router = APIRouter(prefix="/user", tags=["Create User"])


# OAuth2 scheme definition
oauth_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

# Context definition for hashing passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def user_authenticate_credentials(
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
    user = user_get(username, session)

    # !(a && b) === !a || !b
    if not (user and pwd_context.verify(password, user.password)):
        return None

    return user


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
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
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
            UserPermissions,
            Depends(user_get_current),
        ],
    ) -> bool:
        if isinstance(user, NoneType):
            return False  # code IS reachable
        if self.user_is_allowed(user.permissions):
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
        status=2,
        password=pwd_context.hash(user_dict["password"]),
    )

    session.add(user)
    session.commit()

    return user


@router.post("/create")
async def user_create(
    request: UserCreate,
    su: Annotated[
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
    if su:
        user = user_create_superuser(request.model_dump(), session)
        return UserBase(username=user.username, email=user.email)

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
