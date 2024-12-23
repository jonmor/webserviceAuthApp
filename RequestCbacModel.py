from pydantic import BaseModel


class RequestCbacModel(BaseModel):
    username: str
    seed: str
    token: str
    transactionId: str