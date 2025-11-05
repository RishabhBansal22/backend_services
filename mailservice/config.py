from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    redis_host : str
    redis_port : int

    model_config = SettingsConfigDict(env_file=r"d:\AI_coding\MICROSERVICE_TUTORIAL\mailservice\.env")


settings = Settings()