from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    JWT_SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    DRIVER:str
    HOST:str
    PORT:int
    USER:str
    PASSWORD:str
    DATABASE:str 

    #redis
    REDIS_HOST:str
    REDIS_PORT:int

    model_config = SettingsConfigDict(env_file=r"D:\AI_coding\MICROSERVICE_TUTORIAL\auth\.env")


settings = Settings()
try:
    db_url_str = f"mysql+{settings.DRIVER}://{settings.USER}:{settings.PASSWORD}@{settings.HOST}:{settings.PORT}/{settings.DATABASE}"
except Exception as e:
    print(e)



