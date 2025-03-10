from pydantic_settings import BaseSettings, SettingsConfigDict


class SettingsBase(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="app/settings/.env",
        extra="ignore",
    )

    db_user: str
    db_pass: str

    db_host: str
    db_port: int
    db_name: str

    jwt_secret: str
    jwt_algorithm: str
    jwt_expire_min: int


class SettingsPrefix(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="app/settings/.env",
        extra="ignore",
    )

    table_prefix: str


class SettingsEngine(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="app/settings/.env",
        extra="ignore",
    )

    engine: str

    def get_updated_at(self):
        if self.engine == "mysql":
            updated_at_text = "CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
        else:
            updated_at_text = "CURRENT_TIMESTAMP"
        return updated_at_text
