from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from tokens import user_registration, user_login
from config import settings

app = FastAPI()

class NewUser(BaseModel):
    first_name : str = Field(...,min_length=3)
    last_name : Optional[str] = None
    email : EmailStr = Field(...)
    password : str = Field(...,min_length=6)

class Login(BaseModel):
    email : EmailStr = Field(...)
    password : str = Field(...)
    remember_me : Optional[bool] = True


@app.post("/register", status_code=201)
def new_user(user:NewUser):
    first_name = user.first_name
    last_name = user.last_name
    email = user.email
    password = user.password

    result = user_registration(first_name=first_name,
                                 last_name=last_name if last_name else None,
                                 email=email,
                                 password=password)
    
    # Handle different status codes
    if "status_code" in result:
        status_code = result.pop("status_code")
        if status_code != 201:
            raise HTTPException(status_code=status_code, detail=result.get("error", "Registration failed"))
    
    return result

@app.post("/login", status_code=200)
def login(response:Response,user:Login):
    result = user_login(email=user.email, password=user.password)
    
    # Check if login failed (result is a dict with error)
    if isinstance(result, dict):
        status_code = result.get("status_code", 500)
        error_message = result.get("error", "Login failed")
        raise HTTPException(status_code=status_code, detail=error_message)
    
    # Successful login - unpack tokens
    try:
        access_token_tuple, refresh_token_tuple = result
        access_token, access_exp = access_token_tuple
        refresh_token, refresh_exp = refresh_token_tuple
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=500, detail="Invalid token format returned")
    
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    if user.remember_me:
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=expires_in,
            secure=False, #set to true in prod
            samesite="lax"
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            max_age=7*24*60*60,
            secure=False,
            samesite="lax"
        )

        return {
            "message":"login successful, session will persist"
        }
    else:
        return {
            "access_token":access_token,
            "refresh_token":refresh_token,
            "type":"bearer",
            "expires_in":expires_in
        }
