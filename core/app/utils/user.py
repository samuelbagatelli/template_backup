from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User


def user_exists(
    username: str,
    session: Session,
) -> bool:
    query = select(User).where(User.username == username)

    row = session.execute(query).first()

    return row is not None


def user_table_is_empty(session: Session) -> bool:
    query = select(User.id).limit(1)

    row = session.execute(query).first()

    return row is None


def user_get(username: str, session: Session) -> User | None:
    """
    Search a user in the database with the given :username:.

    :raises HTTPException: If the user was not found.
    """
    query = select(User).where(User.username == username)

    row = session.execute(query).first()

    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")

    # the exponentiation operator will destructure
    # the dict returned by row._mapping
    user = User(**row._mapping)

    return user
