from fastapi import FastAPI, Depends, HTTPException, Request, Query, Body, Response, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict

from util.TokenModel import Token
from api.apiWS import api_router
from security.secureWS import secure_router
import uvicorn

# Configuración del secreto y algoritmo para OAuth2
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Base de datos simulada para usuarios y contraseñas
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "password": "testpassword",
        "roles": ["admin", "user"]
    }
}

# Dependencia para OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

FORGEROCK_AM_URL = "https://openam-calasis-demo.forgeblocks.com/am"
VALIDATE_TOKEN_ENDPOINT = f"{FORGEROCK_AM_URL}/json/sessions?_action=validate"
COOKIE_NAME = "6eb8f5a1527322f"

app1 = FastAPI()
app1.include_router(api_router, prefix="/api")
app1.include_router(secure_router, prefix="/security")

async def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or user["password"] != password:
        return None
    return user

async def create_access_token(data: Dict[str, str], roles: list, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "roles": roles})  # Agregar claim adicional
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@app1.get("/")
async def read_root():
    return {"message": "Welcome Security path"}

@app1.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token = create_access_token(
        data={"sub": user["username"]}, roles=user["roles"]
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app1.post("/validate")
async def validate_credentials(
    token: str = Depends(oauth2_scheme)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        #print(payload.items())
        username = payload.get("sub")
        roles = payload.get("roles")
        print(username,roles)
        if username is None or roles is None:
            raise HTTPException(status_code=403, detail="Invalid token")
        return {"username": username, "roles": roles}
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")



if __name__ == "__main__":
    config = uvicorn.Config("app1:app1", port=8000)
    #config = uvicorn.Config("app1:app1", port=8000, ssl_certfile="certs/server.crt", ssl_keyfile="certs/server.key",ssl_ca_certs="certs/ca.crt", log_level="info")
    server = uvicorn.Server(config)
    server.run()