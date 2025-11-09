from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from functions import user_registration, user_login, decode_token, JWTError, create_access_token, get_referesh_token, delete_refresh_token, reset_pass, update_pass_in_db
from config import settings
from datetime import datetime

app = FastAPI()

@app.get("/health")
def health():
    try:
        response = JSONResponse(content="service is running", status_code=200)
        return response
    
    except HTTPException as e:
        return e

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

class ForgetPass(BaseModel):
    email : EmailStr

class ResetPass(BaseModel):
    token : str = Field(...)
    new_pass : str = Field(...,min_length=6,max_length=20)


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
   
    try:
        access_token_tuple, refresh_token_tuple = result
        access_token, _ = access_token_tuple
        refresh_token, _ = refresh_token_tuple
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
    
    
    refresh_token = request.cookies.get("refresh_token")
    
    
    if not refresh_token:
        try:
           
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
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        token_type = payload.get("type")
        if token_type != "refresh_token":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        # Check expiration (exp is Unix timestamp)
        exp: int = payload.get("exp")
        if not exp or exp < datetime.utcnow().timestamp():
            raise HTTPException(status_code=401, detail="Refresh token expired")
        
        db_token = get_referesh_token(user_id=user_id)
        if not db_token or db_token.refresh_token != refresh_token:
            raise HTTPException(status_code=401, detail="Refresh token not found or revoked")
        
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
async def logout(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        try:
            body = await request.json()
            logout_data = Logout(**body)
            refresh_token = logout_data.refresh_token
        except Exception:
            pass  # Body parsing failed, refresh_token remains None
    
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
    
@app.post("/forgetpass")
def forgetpass(request: ForgetPass):
    """
    Initiate password reset flow.
    Validates user email and generates a reset token stored in Redis.
    Returns the reset token (in production, this would be sent via email).
    """
    email : str = request.email
    
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    try:
        from functions import find_user_by_email
        
        
        user = find_user_by_email(email.strip())
        if not user:
            raise HTTPException(
                status_code=404,
                detail="If the email exists, a reset link will be sent"
            )
        
        
        reset_token = reset_pass(user["user_id"],email.strip())
        
        if not reset_token:
            raise HTTPException(
                status_code=500,
                detail="Failed to generate reset token. Please try again later"
            )
        
        # In production, send this token via email instead of returning it
        return {
            "reset_token": reset_token,
            "message": f"Reset link sent to {email}",
            "expires_in": "15 minutes"
        }
    
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        print(f"Error in forgetpass endpoint: {e}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing your request"
        )
        

@app.post("/resetpass")
def reset_password(request: ResetPass):
    """
    Reset user password using a valid reset token.
    Validates the token from Redis and updates the password in the database.
    """
    reset_token = request.token
    new_pass = request.new_pass
    
 
    if not reset_token:
        raise HTTPException(status_code=400, detail="Reset token is required")
    
    if not new_pass:
        raise HTTPException(status_code=400, detail="New password is required")
  
    if len(new_pass) < 6 or len(new_pass) > 20:
        raise HTTPException(
            status_code=400,
            detail="Password must be between 6 and 20 characters"
        )
    
    try:
        update = update_pass_in_db(reset_token, new_pass=new_pass)
        
        if update["status_code"] == 200:
            return {
                "status_code": 200,
                "message": "Password updated successfully"
            }
        elif update["status_code"] == 400:
            raise HTTPException(
                status_code=400,
                detail=update.get("error", "Invalid or expired reset token")
            )
        elif update["status_code"] == 404:
            raise HTTPException(
                status_code=404,
                detail=update.get("error", "User not found")
            )
        else:
            raise HTTPException(
                status_code=500,
                detail=update.get("error", "Failed to update password")
            )
    
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        print(f"Error in resetpass endpoint: {e}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting your password"
        )

        





        
