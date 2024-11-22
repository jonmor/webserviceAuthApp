from fastapi import FastAPI, Depends, HTTPException, Request, Query, Body, Path, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
#import requests
from jose import JWTError, jwt
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, Dict



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

app = FastAPI()

# Modelo para la entrada y salida del servicio
class UserCredentials(BaseModel):
    user: str
    password: str
    roles: list

class Token(BaseModel):
    access_token: str
    token_type: str

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or user["password"] != password:
        return None
    return user

def create_access_token(data: Dict[str, str], roles: list, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "roles": roles})  # Agregar claim adicional
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token = create_access_token(
        data={"sub": user["username"]}, roles=user["roles"]
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/validate")
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

#Integracion de pruebas para PingGateway



# Modelo para los datos en JSON (POST)
class InputData(BaseModel):
    idTransferencia: str
    monto: int

@app.get("/api/transferencia")
@app.post("/api/transferencia")
async def transferencia(
    request: Request,
        monto: Optional[int] = Query(None, description="Monto a recibir en la trasferencia"),
        idTransferencia: Optional[str] = Query(None, description="ID de trasferencia"),
        body: Optional[InputData] = Body(None)
):
    # Determinar si es GET o POST
    method = request.method
    if method == "POST" and body:
        result = {
            "status": "success",
            "monto": body.monto
        }

    elif method == "POST" and monto and idTransferencia:
        result = {
            "status": "success",
            "monto": body.monto
        }

    elif method == "GET" and monto and idTransferencia:
        result = {
            "status": "success",
            "monto": monto
        }

    return result




@app.get("/api/retiro")
@app.post("/api/retiro")
async def retiro(
    request: Request,
        monto: Optional[int] = Query(None, description="Monto a recibir en la trasferencia"),
        idTransferencia: Optional[str] = Query(None, description="ID de trasferencia"),
        body: Optional[InputData] = Body(None)
):
    # Determinar si es GET o POST
    method = request.method
    if method == "POST" and body:
        result = {
            "status": "success",
            "monto": body.monto
        }
        return result

    elif method == "POST" and monto and idTransferencia:
        result = {
            "status": "success",
            "monto": monto
        }
        return result

    elif method == "GET" and monto and idTransferencia:
        result = {
            "status": "success",
            "monto": monto
        }
        return result
    else:
        result = {
            "status": "error",
            "message": "Faltan parámetros en la solicitud"
        }
        return result


app.get("/api/{wildcard:path}/redirect")
async def cdsso_redirect(token: str, app_redirect: str):
    """
    Endpoint para manejar CDSSO.
    - token: El SSO token de ForgeRock.
    - app_redirect: URL de la aplicación destino.
    """
    # Validar el token con ForgeRock AM
    headers = {
        "Content-Type": "application/json",
        "iPlanetDirectoryPro": token  # Incluye el token en el encabezado
    }

    try:
        response = Response.post(VALIDATE_TOKEN_ENDPOINT, headers=headers, timeout=10)
        response_data = response.json()

        if response.status_code != 200 or not response_data.get("valid"):
            raise HTTPException(status_code=401, detail="Token inválido o sesión no válida")

        # Token válido, redirigir al usuario a la app destino
        return RedirectResponse(url=app_redirect)

    except Response.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error al conectar con ForgeRock: {str(e)}")