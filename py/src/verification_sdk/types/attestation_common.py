from dataclasses import dataclass
from typing import Literal
from pydantic import BaseModel


SigningAlgo = Literal["ecdsa", "ed25519"]


@dataclass
class TcbInfo(BaseModel):
    app_compose: str

