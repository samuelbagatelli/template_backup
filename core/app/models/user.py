from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, SmallInteger, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql.elements import TextClause

from app.prefix.prefix_base import PrefixBase
from app.settings.config import SettingsEngine


class User(PrefixBase):
    __incomplete_tablename__ = "user"

    id: Mapped[BigInteger] = mapped_column(
        BigInteger, primary_key=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=TextClause("CURRENT_TIMESTAMP"),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=TextClause(
            SettingsEngine().get_updated_at(),  # pyright: ignore
        ),
        nullable=False,
    )

    username: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        unique=True,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(150),
        unique=True,
        index=True,
        nullable=False,
    )

    first_name: Mapped[str] = mapped_column(String(50), nullable=False)
    last_name: Mapped[str] = mapped_column(String(50), nullable=False)

    password: Mapped[str] = mapped_column(String(255), nullable=False)

    status: Mapped[str] = mapped_column(
        SmallInteger,
        nullable=False,
        server_default=TextClause("1"),
        comment="[1 - Pending, 2 - Active, 3 - Disabled]",
    )
    superuser: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=TextClause("FALSE"),
    )

    deleted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=TextClause("FALSE"),
    )

    def __repr__(self) -> str:
        return f"{self.id}."
