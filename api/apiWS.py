from wsgiref.validate import header_re

from fastapi import APIRouter
from fastapi import HTTPException, Request, Query, Body, Response
from typing import Optional
from starlette.responses import RedirectResponse
from util.InputData import InputData

api_router = APIRouter()

FORGEROCK_AM_URL = "https://openam-calasis-demo.forgeblocks.com/am"
VALIDATE_TOKEN_ENDPOINT = f"{FORGEROCK_AM_URL}/json/sessions?_action=validate"
COOKIE_NAME = "6eb8f5a1527322f"

@api_router.get("/")
async def read_root():
    return {"message": "Welcome API path"}

@api_router.get("/transferencia")
@api_router.post("/transferencia")
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

@api_router.get("/retiro")
@api_router.post("/retiro")
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


@api_router.post("/{wildcard:path}/redirect")
async def cdsso_redirect(request: Request):
    headers = request.headers
    cookies = request.cookies
    query_params = request.query_params
    print(query_params)
    print(headers)
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="No contenido")
    id_token = body.decode("utf-8").replace("id_token=","")
    print("Body:"+ id_token)
    print(cookies)
    current_url = str(request.url)
    print(current_url)
    #new_url = current_url.replace("http://localhost:8000", "https://sdkapp.tsa.com.mx:8443")
    new_url = current_url.replace("/redirect","")
    print(new_url)
    redirect_response =  RedirectResponse(url=new_url, status_code=302)
    print("Add Headers")
    for header_name, header_value in headers.items():
    #    print(header_name)
        if (header_name == "origin"
                or header_name == "referer"
                or header_name == "sec-fetch-site"
                or header_name == "Forwarded"
                or header_name == "X-Forwarded"):
            print("Added: "+header_name+ ":" + header_value)
            redirect_response.headers[header_name] = header_value
        else:
            print("Not Added: " + header_name + ":" + header_value)
    print("Add Cookies")
    for cookie_name, cookie_value in cookies.items():
        redirect_response.set_cookie(key = cookie_name, value = cookie_value)
    print("Add custom Cookie and header")
    redirect_response.headers["ig-token-cookie"] = id_token
    #redirect_response.headers["host"] = "sdkapp.tsa.com.mx:8443"
    redirect_response.headers["host"] = "localhost:8000"

    redirect_response.set_cookie(key="ig-token-cookie", value=id_token)
    return redirect_response
    #return {"headers": dict(headers), "query_params": dict(query_params)}



""""
async def cdsso_redirect(token: str, app_redirect: str):
    # Validar el token con ForgeRock AM
    headers = {
        "Content-Type": "application/json",
        "iPlanetDirectoryPro": token  # Incluye el token en el encabezado
    }

    print("entrando a redirect-------------")

    try:
        response = Response.post(VALIDATE_TOKEN_ENDPOINT, headers=headers, timeout=10)
        response_data = response.json()

        if response.status_code != 200 or not response_data.get("valid"):
            raise HTTPException(status_code=401, detail="Token inválido o sesión no válida")

        # Token válido, redirigir al usuario a la app destino
        return RedirectResponse(url=app_redirect)

    except Response.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error al conectar con ForgeRock: {str(e)}")
"""