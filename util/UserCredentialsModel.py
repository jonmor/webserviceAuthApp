from pydantic import BaseModel


# Modelo para la entrada y salida del servicio
class UserCredentials(BaseModel):
    user: str
    password: str
    roles: list