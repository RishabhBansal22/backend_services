import random
import requests
from config import settings


def smtp_send_mail(email:str,token:str,exp:str,test_mode=True):
    if test_mode:
        try:
            url = "https://{host}/reset_password?reset_token={token}"
            return {
                "message":f"mail to {email} with {token} and expire in {exp} sent successfully"
            }
        except Exception as e:
            return e
    else:
        pass


def test_passreset_flow(token:str):
    
    dummy_pass = ["admin@123","usernew","dummypass",'fromemail',"servicepass"]
    new_pass = random.choice(dummy_pass)

    payload = {
        "token":token,
        "new_pass":new_pass
    }

    req = requests.post(url="http://127.0.0.1:8000/resetpass",json=payload)
    return req.status_code, req.json() if req.status_code == 200 else req.text

