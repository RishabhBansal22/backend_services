from fastapi import FastAPI, HTTPException, Cookie, Request
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from tokens import user_registration, user_login, decode_token, JWTError, create_access_token, get_referesh_token, delete_refresh_token
from config import settings
from datetime import datetime

app = FastAPI()

class NewUser(BaseModel):
    first_name : str = Field(...,min_length=3)
    last_name : Optional[str] = None
    email : EmailStr = Field(...)
    password : str = Field(...,min_length=6,max_length=20)

class Login(BaseModel):
    email : EmailStr = Field(...)
    password : str = Field(...)
    remember_me : Optional[bool] = True

class RefreshToken(BaseModel):
    refresh_token : Optional[str] = None


class Logout(BaseModel):
    access_token : str
    refresh_token : str



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


@app.post("/refresh")
async def refresh_token(response: Response, request: Request):
    
    # Get refresh token from cookie first
    refresh_token = request.cookies.get("refresh_token")
    
    # If not in cookie, try to parse from request body
    if not refresh_token:
        try:
            # Parse body as RefreshToken model for validation
            body = await request.json()
            token_data = RefreshToken(**body)
            refresh_token = token_data.refresh_token
        except Exception:
            pass  # Body parsing/validation failed, token remains None
    
    if not refresh_token:
        raise HTTPException(
            status_code=400, 
            detail="Refresh token must be provided in cookie or request body"
        )
    
    # Token verification
    try:
        payload: dict = decode_token(token=refresh_token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        # Get user_id from "sub" field (not "user_id")
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        # Verify token type
        token_type = payload.get("type")
        if token_type != "refresh_token":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        # Check expiration (exp is Unix timestamp)
        exp: int = payload.get("exp")
        if not exp or exp < datetime.utcnow().timestamp():
            raise HTTPException(status_code=401, detail="Refresh token expired")
        
        # Validate refresh token against database (for revocation/logout support)
        db_token = get_referesh_token(user_id=user_id)
        if not db_token or db_token.refresh_token != refresh_token:
            raise HTTPException(status_code=401, detail="Refresh token not found or revoked")
        
        # Create new access token
        access_token, expire_time = create_access_token(user_id=user_id)
        if not access_token:
            raise HTTPException(status_code=500, detail="Failed to create access token")
        
        # Calculate expires_in seconds
        expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        
        json_content = {
            "access_token": access_token,
            "type": "bearer",
            "expires_in": expires_in
        }
        
        # If refresh token came from cookie, set access token in cookie too
        if request.cookies.get("refresh_token"):
            json_response = JSONResponse(content=json_content)
            json_response.set_cookie(
                key="access_token",
                value=access_token,
                max_age=expires_in,
                httponly=True,
                samesite="lax",
                secure=False  # Set to True in production
            )
            return json_response
        else:
            return JSONResponse(content=json_content)
    
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        print(f"Error in refresh endpoint: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/logout")
async def logout(request: Request, response: Response):
    # Try to get refresh token from cookies first
    refresh_token = request.cookies.get("refresh_token")
    
    # If not in cookies, try request body
    if not refresh_token:
        try:
            body = await request.json()
            logout_data = Logout(**body)
            refresh_token = logout_data.refresh_token
        except Exception:
            pass  # Body parsing failed, refresh_token remains None
    
    # If still no refresh token, return error
    if not refresh_token:
        raise HTTPException(
            status_code=400,
            detail="Refresh token must be provided in cookies or request body"
        )
    
    # Delete refresh token from database
    result = delete_refresh_token(refresh_token)
    
    if result["status_code"] == 200:
        # Check if cookies exist and delete them
        if request.cookies.get("refresh_token") or request.cookies.get("access_token"):
            json_response = JSONResponse(
                content={"message": "Logout successful"}
            )
            json_response.delete_cookie(
                key="access_token",
                httponly=True,
                samesite="lax"
            )
            json_response.delete_cookie(
                key="refresh_token",
                httponly=True,
                samesite="lax"
            )
            return json_response
        else:
            return {
                "message": "Logout successful, please delete tokens from local storage"
            }
    elif result["status_code"] == 404:
        raise HTTPException(
            status_code=404,
            detail="Refresh token not found or already logged out"
        )
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to logout"
        )
        
