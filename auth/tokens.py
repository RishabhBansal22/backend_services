from config import settings
from database import Session, Users, RefreshToken
import bcrypt
from datetime import datetime, timedelta
from jose import jwt, JWTError
import uuid

try:
    JWT_SECRET = settings.JWT_SECRET_KEY
    TOKEN_TIMEOUT = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    REFRESH_TOKEN_TIMEOUT : int= 7
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
    # Normalize email to lowercase
    email = email.lower().strip()
    
    user_id = str(uuid.uuid4())
    hashed_password = hash_password(password)
    created_time = datetime.utcnow()
    
    user = Users(
        id=user_id,
        first_name=first_name.strip(),
        last_name=last_name.strip() if last_name else None,
        email=email,
        password=hashed_password,
        created_at=created_time
    )
    
    with Session() as session:
        try:
            existing_user = session.query(Users).filter_by(email=email).first()
            if existing_user:
                return {
                    "error": "Registration failed",
                    "status_code": 409
                }
            
            session.add(user)
            session.commit()
            
            # Return the user data directly without another DB query
            return {
                "new_user": {
                    "user_id": user_id,
                    "name": first_name + (" " + last_name if last_name else ""),
                    "email": email,
                    "created_at": created_time.isoformat()
                },
                "status_code": 201
            }
        except Exception as e:
            session.rollback()
            # Check if it's a unique or duplicate entry constraint violation
            if "unique" in str(e).lower() or "duplicate" in str(e).lower():
                return {
                    "error": "Registration failed",
                    "status_code": 409
                }
            return {
                "error": f"An error occurred during registration",
                "status_code": 500
            }
    

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
    
def create_token(data:dict, expires_delta:timedelta):
    to_encode = data.copy()
    expire_time = datetime.utcnow() + expires_delta
    to_encode.update({
        "exp":expire_time
    })
    
    try:
        access_token = jwt.encode(to_encode,key=JWT_SECRET,algorithm=ALGORITHM)
        return access_token, expire_time
    except:
        return JWTError
    
def decode_token(token:str):
    try:
        payload = jwt.decode(token,JWT_SECRET,ALGORITHM)
        return payload
    except JWTError:
        return JWTError
    
def save_refresh_token(user_id:str,referesh_token:str):
    with Session() as session:
        try:
            existing_token = session.query(RefreshToken).filter_by(user_id=user_id).first()
            if existing_token.refresh_token:
                existing_token.refresh_token = referesh_token
                existing_token.created_at = datetime.utcnow()
            else:
                new_token = RefreshToken(
                    user_id=user_id,
                    refresh_token=referesh_token,
                    created_at = datetime.utcnow()
                )
                session.add(new_token)
                session.commit()
        except Exception as e:
            return e

def get_referesh_token(user_id:str):
    with Session() as session:
        try:
            ref_token = session.query(RefreshToken).filter_by(user_id=user_id).first()
            if ref_token:
                return ref_token
        except Exception as e:
            return e

def find_user_by_email(email:str) -> dict:
    session = Session()
    try:
        # Normalize email to lowercase for case-insensitive comparison
        user_data_obj = session.query(Users).filter_by(email=email.lower()).first()
        
        if user_data_obj is None:
            return None

        user_data = {
            "user_id":user_data_obj.id,
            "first_name":user_data_obj.first_name,
            "last_name":user_data_obj.last_name,
            "email":user_data_obj.email,
            "hashed_pass":user_data_obj.password

        }
        return user_data
    except Exception as e:
        print(f"Error in find_user_by_email: {e}")
        return None
    finally:
        session.close()

def find_user_by_id(user_id: str):
    session = Session()
    try:
        user = session.query(Users).filter(Users.id == user_id).first()
        if user:
            return {
                "id": user.id,
                "email": user.email,
                "hashed_password": user.password,
                "first_name": user.first_name,
                "created_at": user.created_at
            }
        return None
    finally:
        session.close()
        



# if __name__ == "__main__":
#     user_data = find_user_by_email("test1@gmail.com")
#     token, exp_time = create_token(user_data,timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
#     print("ACCESS_TOKEN :",token)
#     print("EXP_TIME",exp_time)
#     print("========================")
#     decode = decode_token(token)
#     print("DECODE : ",decode)
    
