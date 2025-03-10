from app.settings.config import SettingsBase
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

settings = SettingsBase()  # pyright: ignore

SQL_DB_URL = (
    f"mysql+mysqldb://"
    f"{settings.db_user}"
    f":{settings.db_pass}"
    f"@{settings.db_host}"
    f":{settings.db_port}"
    f"/{settings.db_name}"
)

engine = create_engine(SQL_DB_URL)
SessionLocal = sessionmaker(autoflush=False, bind=engine)

Base = declarative_base()


def get_session():
    """
    Creates a ORM local session with the database and closes it when finished.

    :yield: A Session connection with the database.
    :rtype: class:`sqlalchemy.orm.Session`
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
