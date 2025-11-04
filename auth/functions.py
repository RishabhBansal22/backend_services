from config import settings
from database import Session, Users, RefreshToken
from redis_cache import conn
import bcrypt
from datetime import datetime, timedelta
from jose import jwt, JWTError
import uuid
import redis

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
    # Normalize email to lowercase and strip whitespace
    email = email.lower().strip()
    
    # Strip whitespace from names
    first_name = first_name.strip()
    last_name = last_name.strip() if last_name else None
    
    user_id = str(uuid.uuid4())
    hashed_password = hash_password(password)
    created_time = datetime.utcnow()
    
    user = Users(
        id=user_id,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        created_at=created_time
    )
    
    with Session() as session:
        try:
            existing_user = session.query(Users).filter_by(email=email).first()
            if existing_user:
                print("user already exists")
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
    try:
        # Normalize email
        email = email.lower().strip()
        
        user_data = find_user_by_email(email)
        if not user_data:
            return {
                "error": "Invalid email or password",
                "status_code": 401
            }
        
        # Verify password
        verify = varify_password(raw_pass=password, hash_pass=user_data["hashed_pass"])
        if not verify:
            return {
                "error": "Invalid email or password",
                "status_code": 401
            }
        
        # Create access token
        access_token_result = create_token({
            "sub": user_data["user_id"],
            "email": user_data["email"]
        },
        expires_delta=timedelta(minutes=TOKEN_TIMEOUT))
        
        # Check if token creation failed
        if access_token_result == JWTError or not isinstance(access_token_result, tuple):
            return {
                "error": "Failed to create access token",
                "status_code": 500
            }
        
        access_token, access_exp = access_token_result

        # Create refresh token
        refresh_token_result = create_token(
            {
                "sub": user_data["user_id"],
                "type": "refresh_token"
            },
            expires_delta=timedelta(days=REFRESH_TOKEN_TIMEOUT)
        )
        
        # Check if token creation failed
        if refresh_token_result == JWTError or not isinstance(refresh_token_result, tuple):
            return {
                "error": "Failed to create refresh token",
                "status_code": 500
            }
        
        refresh_token, refresh_exp = refresh_token_result
        
        # Save refresh token to database
        save_result = save_refresh_token(user_id=user_data["user_id"], referesh_token=refresh_token)
        if save_result and isinstance(save_result, Exception):
            return {
                "error": "Failed to save refresh token",
                "status_code": 500
            }

        return (access_token, access_exp), (refresh_token, refresh_exp)
    
    except Exception as e:
        print(f"Error in user_login: {e}")
        return {
            "error": "An unexpected error occurred during login",
            "status_code": 500
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
    except Exception as e:
        print(f"Error creating token: {e}")
        return None
    

def create_access_token(user_id:str):
    user = find_user_by_id(user_id)
    if not user:
        return None, None
    user_email = user.get("email")
    time_delta = timedelta(minutes=TOKEN_TIMEOUT)
    access_token, expire_time = create_token(
        {
            "sub":user_id,
            "email":user_email
        },
        expires_delta=time_delta

    )
    return access_token, expire_time
    
def decode_token(token:str):
    try:
        payload = jwt.decode(token,JWT_SECRET,algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        print(f"Error decoding token: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error decoding token: {e}")
        return None
    
def save_refresh_token(user_id:str,referesh_token:str):
    with Session() as session:
        try:
            existing_token = session.query(RefreshToken).filter_by(user_id=user_id).first()
            if existing_token:
                # Update existing token
                existing_token.refresh_token = referesh_token
                existing_token.created_at = datetime.utcnow()
            else:
                # Create new token
                new_token = RefreshToken(
                    user_id=user_id,
                    refresh_token=referesh_token,
                    created_at = datetime.utcnow()
                )
                session.add(new_token)
            
            session.commit()
            return None  # Success
        except Exception as e:
            session.rollback()
            print(f"Error saving refresh token: {e}")
            return e

def get_referesh_token(user_id:str):
    with Session() as session:
        try:
            ref_token = session.query(RefreshToken).filter_by(user_id=user_id).first()
            if ref_token:
                return ref_token
        except Exception as e:
            return e
        
def delete_refresh_token(refresh_token):
    "delete refresh token row in case of logout"
    with Session() as session:
        try:
            token_entry = session.query(RefreshToken).filter_by(refresh_token=refresh_token).first()
            if token_entry:
                session.delete(token_entry)
                session.commit()
                return {
                    "status_code": 200,
                    "message": "Token deleted successfully"
                }
            else:
                return {
                    "status_code": 404,
                    "message": "Token not found"
                }
        except Exception as e:
            session.rollback()
            print(f"Error deleting refresh token: {e}")
            return {
                "status_code": 500,
                "message": "Failed to delete token"
            }


def find_user_by_email(email:str) -> dict:
    session = Session()
    try:
        # Normalize email to lowercase and strip whitespace for case-insensitive comparison
        user_data_obj = session.query(Users).filter_by(email=email.lower().strip()).first()
        
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
                "user_id": user.id,
                "email": user.email,
                "hashed_password": user.password,
                "first_name": user.first_name,
                "created_at": user.created_at
            }
        return None
    finally:
        session.close()
        
def reset_pass(user_id):
    """
    Generate a password reset token and store it in Redis.
    Returns the reset token string on success, None on failure.
    Token expires in 15 minutes (900 seconds).
    """
    if not conn:
        print("Redis connection not available")
        return None
    
    try:
        # Generate a unique reset token
        reset_token = str(uuid.uuid4())
        
        # Store in Redis with user_id as value
        # Key format: password_reset:<token>
        redis_key = f"password_reset:{reset_token}"
        
        # Set token with 15 minute expiration (900 seconds)
        conn.setex(redis_key, 900, user_id)
        
        print(f"Reset token created for user {user_id}")
        return reset_token
    
    except redis.RedisError as e:
        print(f"Redis error in reset_pass: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in reset_pass: {e}")
        return None


def update_pass_in_db(reset_token: str, new_pass: str):
    """
    Update user password using a valid reset token.
    Returns dict with status_code and message.
    """
    if not conn:
        return {
            "status_code": 500,
            "error": "Redis connection not available"
        }
    
    if not reset_token or not new_pass:
        return {
            "status_code": 400,
            "error": "Reset token and new password are required"
        }
    
    try:
        # Retrieve user_id from Redis using the reset token
        redis_key = f"password_reset:{reset_token}"
        user_id = conn.get(redis_key)
        
        if not user_id:
            return {
                "status_code": 400,
                "error": "Invalid or expired reset token"
            }
        
        # Redis returns bytes, decode to string
        if isinstance(user_id, bytes):
            user_id = user_id.decode('utf-8')
        
        # Hash the new password
        new_pass_hash = hash_password(new_pass.strip())
        
        with Session() as session:
            try:
                # Find user by id (not user_id)
                user = session.query(Users).filter_by(id=user_id).first()
                
                if not user:
                    return {
                        "status_code": 404,
                        "error": "User not found"
                    }
                
                # Update password
                user.password = new_pass_hash
                session.commit()
                
                # Delete any existing refresh token for this user (invalidate all sessions)
                try:
                    existing_refresh_token = session.query(RefreshToken).filter_by(user_id=user_id).first()
                    if existing_refresh_token:
                        session.delete(existing_refresh_token)
                        session.commit()
                        print(f"Deleted existing refresh token for user {user_id}")
                except Exception as token_delete_error:
                    # Log but don't fail the password update if token deletion fails
                    print(f"Warning: Failed to delete refresh token: {token_delete_error}")
                
                # Delete the reset token from Redis after successful password update
                conn.delete(redis_key)
                
                print(f"Password updated successfully for user {user_id}")
                return {
                    "status_code": 200,
                    "message": "Password updated successfully. All sessions have been logged out."
                }
            
            except Exception as e:
                session.rollback()
                print(f"Database error in update_pass_in_db: {e}")
                return {
                    "status_code": 500,
                    "error": "Failed to update password in database"
                }
    
    except redis.RedisError as e:
        print(f"Redis error in update_pass_in_db: {e}")
        return {
            "status_code": 500,
            "error": "Redis error occurred"
        }
    except Exception as e:
        print(f"Unexpected error in update_pass_in_db: {e}")
        return {
            "status_code": 500,
            "error": "An unexpected error occurred"
        }


# if __name__ == "__main__":
#     user_data = find_user_by_email("test1@gmail.com")
#     token, exp_time = create_token(user_data,timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
#     print("ACCESS_TOKEN :",token)
#     print("EXP_TIME",exp_time)
#     print("========================")
#     decode = decode_token(token)
#     print("DECODE : ",decode)
    
