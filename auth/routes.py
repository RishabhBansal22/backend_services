from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from tokens import user_registration

app = FastAPI()

class NewUser(BaseModel):
    first_name : str = Field(...,min_length=3)
    last_name : Optional[str] = None
    email : EmailStr = Field(...)
    password : str = Field(...,min_length=6)


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
