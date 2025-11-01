from config import db_url_str
from sqlalchemy import create_engine, Column, String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime


try:
    engine = create_engine(db_url_str,echo=True)
except Exception as e:
    print(e)


Base = declarative_base()

class Users(Base):
    __tablename__ = "users"

    id = Column(String(200), primary_key=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50))
    email = Column(String(50), unique=True, nullable=False, index=True)
    password = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    refresh_token = relationship("RefreshToken", back_populates="user", uselist=False, cascade="all, delete-orphan")


class RefreshToken(Base):
    __tablename__ = "refresh_token"

    user_id = Column(String(200), ForeignKey("users.id"), primary_key=True)
    refresh_token = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("Users", back_populates="refresh_token")


Session = sessionmaker(bind=engine)


def create_new_table():
    Base.metadata.create_all(engine)

if __name__ == "__main__":
    create_new_table()
   