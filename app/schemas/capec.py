from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class CAPECBase(BaseModel):
    capec_id: str
    name: str
    description: Optional[str] = None
    likelihood_of_attack: Optional[str] = None
    typical_severity: Optional[str] = None
    related_weaknesses: Optional[str] = None
    prerequisites: Optional[str] = None
    mitigations: Optional[str] = None
    consequences: Optional[str] = None
    example_instances: Optional[str] = None

class CAPECCreate(CAPECBase):
    pass

class CAPEC(CAPECBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = {
        "from_attributes": True
    }