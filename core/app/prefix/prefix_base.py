from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import DeclarativeBase

from app.settings.config import SettingsPrefix


class PrefixDeclarativeBase(DeclarativeBase):
    pass


class PrefixBase(PrefixDeclarativeBase):
    settings = SettingsPrefix()  # pyright: ignore
    __abstract__ = True
    _the_prefix = settings.table_prefix

    @declared_attr
    def __tablename__(cls):
        return cls._the_prefix + cls.__incomplete_tablename__
