from app.settings.config import SettingsPrefix
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import DeclarativeBase


class PrefixDeclarativeBase(DeclarativeBase):
    pass


class PrefixBase(PrefixDeclarativeBase):
    # settings = SettingsPrefix()  # pyright: ignore
    __abstract__ = True
    _the_prefix = SettingsPrefix().table_prefix  # pyright: ignore

    @declared_attr
    def __tablename__(cls):
        return cls._the_prefix + cls.__incomplete_tablename__
