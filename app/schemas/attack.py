from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AttackBase(BaseModel):
    technique_id: str
    external_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    platforms: Optional[str] = None
    tactics: Optional[str] = None
    data_sources: Optional[str] = None
    detection: Optional[str] = None
    permissions_required: Optional[str] = None
    url: Optional[str] = None

class AttackCreate(AttackBase):
    pass

class Attack(AttackBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = {
        "from_attributes": True
    }