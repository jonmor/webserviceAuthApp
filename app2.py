from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request, Query, Body, Response, Header, APIRouter
from pydantic import BaseModel
import uvicorn


secure_router = FastAPI()


class RequestCbacModel(BaseModel):
    username: str
    seed: str
    token: str
    transactionId: str

@secure_router.get("/")
async def read_root():
    return {"message": "Welcome Security path"}

@secure_router.post("/security/cbac/validate")
async def cbac_validate(cbacModel: RequestCbacModel, x_api_key: Optional[str] = Header(None)):
    # Validar el header 'api-key'
    if not x_api_key or x_api_key is None:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    # Respuesta en caso de éxito
    print(x_api_key)
    print(cbacModel.token)
    print(cbacModel.username)
    print(cbacModel.seed)
    if(cbacModel.token == "211111"):
        return {
            "data": {
                "status": "INVALID",
                "transactionId": cbacModel.transactionId
            }
        }
    else:
        return {
            "data": {
                "status": "SUCCESS",
                "transactionId": cbacModel.transactionId
            }
        }

if __name__ == "__main__":
    config = uvicorn.Config("app2:secure_router",
                            port=8443,host="0.0.0.0",
                            ssl_certfile="certs/server.crt",
                            ssl_keyfile="certs/server.key",
                            ssl_ca_certs="certs/ca.crt",
                            log_level="info")
    server = uvicorn.Server(config)
    server.run()