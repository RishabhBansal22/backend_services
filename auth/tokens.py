import os
from config import settings
from database import Session, Users
import bcrypt
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Dict, Optional
import uuid

try:
    JWT_SECRET = settings.JWT_SECRET_KEY
    TOKEN_TIMEOUT = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    REFRESH_TOKEN_TIMEOUT = 7
except:
    print(KeyError)

ALGORITHM = "HS256"

def hash_password(password:str) -> str:
    salt = bcrypt.gensalt()
    hashed_pass = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_pass.decode('utf-8')

def varify_password(raw_pass:str, hash_pass:str) -> bool:
    return bcrypt.checkpw(raw_pass.encode('utf-8'), hash_pass.encode('utf-8'))

def user_registration(first_name:str,email:str, password:str,last_name:str=None):
    if find_user_by_email(email):
        return {
            "warning":"user already exists, please login instead"
        }
    else:
        user_id = uuid.uuid4()
        password = hash_password(password)
        user = Users(
            id=str(user_id),first_name=first_name,last_name=last_name,email=email,password=password,
            created_at=datetime.now()
            )
        print(f"adding user {user.first_name}")
        with Session() as session:
            session.add(user)
            session.commit()
            print(f"{first_name} with {email} has been added to db")
    

def user_login(email:str,password:str):
    user_data = find_user_by_email(email)
    if user_data:
        verify = varify_password(raw_pass=password, hash_pass=user_data["hashed_pass"])
        if verify:
            return {
                "status":f"verification successfull, welcome {user_data['first_name']}"
            }
        else:
            return{
                "status":"401"
            }
    else:
        return {
            "error":"no user found"
        }

def find_user_by_email(email:str) -> dict:
    try:
        session = Session()
        user_data_obj = session.query(Users).filter_by(email=email).first()

        user_data = {
            "user_id":user_data_obj.id,
            "first_name":user_data_obj.first_name,
            "last_name":user_data_obj.last_name,
            "email":user_data_obj.email,
            "hashed_pass":user_data_obj.password

        }
        return user_data
    except Exception as e:
        print(e)
    finally:
        session.close()
        



if __name__ == "__main__":
    pass
    #     first_name="test2",
        
    #     password="abcd1234",
    #     email="test2@gmail.com"

    # )
    # print(register)
    # login_test = user_login(email="test2@gmail.com",password="abcd1234")
    # print(login_test)
