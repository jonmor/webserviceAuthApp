from pydantic import BaseModel


class InputData(BaseModel):
    idTransferencia: str
    monto: int