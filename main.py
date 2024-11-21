from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import Optional

# Configuración del secreto y algoritmo para OAuth2
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Base de datos simulada para usuarios y contraseñas
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "password": "testpassword"
    }
}

# Dependencia para OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# Modelo para la entrada y salida del servicio
class UserCredentials(BaseModel):
    user: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or user["password"] != password:
        return False
    return True

def create_access_token(data: dict, expires_delta: Optional[int] = None):
    to_encode = data.copy()
    if expires_delta:
        to_encode.update({"exp": expires_delta})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token(data={"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/validate", response_model=bool)
async def validate_credentials(
    credentials: UserCredentials, token: str = Depends(oauth2_scheme)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username or not authenticate_user(credentials.user, credentials.password):
            raise HTTPException(status_code=403, detail="Invalid credentials")
        return True
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")