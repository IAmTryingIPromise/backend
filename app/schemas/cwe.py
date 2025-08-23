from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class CWEBase(BaseModel):
    cwe_id: str
    name: str
    description: Optional[str] = None
    common_consequenses: Optional[str] = None
    potential_mitigations: Optional[str] = None

class CWECreate(CWEBase):
    pass

class CWE(CWEBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = {
        "from_attributes": True
    }