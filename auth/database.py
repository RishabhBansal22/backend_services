from config import settings, db_url_str
from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import uuid

try:
    engine = create_engine(db_url_str,echo=True)
except Exception as e:
    print(e)


Base = declarative_base()

class Users(Base):
    __tablename__ = "users"
    id = Column(String(length=100), primary_key=True)
    first_name = Column(String(length=50))
    last_name = Column(String(length=50))
    email = Column(String(length=50))
    password = Column(String(length=100))
    created_at = Column(DateTime)

class RefreshToken(Base):
    __tablename__ = "refresh_token"
    user_id = Column(String(length=100), primary_key=True)
    refresh_token = Column(String(length=100))
    created_at = Column(DateTime)


Session = sessionmaker(bind=engine)


def create_new_table():
    Base.metadata.create_all(engine)

# if __name__ == "__main__":
#     create_new_table()
    # session = Session()
    # dummy_users = [
    #     Users(id=str(uuid.uuid4()), first_name="John", last_name="Doe", email="john.doe@example.com", password="password123", created_at=datetime.now()),
    #     Users(id=str(uuid.uuid4()), first_name="Jane", last_name="Smith", email="jane.smith@example.com", password="password456", created_at=datetime.now()),
    #     Users(id=str(uuid.uuid4()), first_name="Peter", last_name="Jones", email="peter.jones@example.com", password="password789", created_at=datetime.now())
    # ]
    # session.add_all(dummy_users)
    # session.commit()
    # session.close()
    # print("Dummy users added to the database.")
    # with Session() as session:
    #     res = session.query(Users).all()
    #     for user in res:
    #         print(user.id, user.first_name, user.last_name, user.email, user.password, user.created_at)
    # register = user_registration(
