from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request, Query, Body, Response, Header, APIRouter
from pydantic import BaseModel

secure_router = APIRouter()


class RequestCbacModel(BaseModel):
    username: str
    seed: str
    token: str
    transactionId: str

@secure_router.get("/")
def read_root():
    return {"message": "Welcome Security path"}

@secure_router.post("/cbac/validate")
async def cbac_validate(request: RequestCbacModel, api_key: Optional[str] = Header(None)):
    # Validar el header 'api-key'
    if not api_key or api_key is None:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    # Respuesta en caso de éxito
    print(api_key)
    print(request.json())
    return {
        "data": {
            "status": "SUCCESS",
            "transactionId": "12345"
        }
    }