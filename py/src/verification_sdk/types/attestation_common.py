from dataclasses import dataclass
from pydantic import BaseModel


@dataclass
class TcbInfo(BaseModel):
    app_compose: str

