from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AssetBase(BaseModel):
    type: str
    model: str
    vendor: str
    department: str
    risk_level: Optional[float] = None

class AssetCreate(AssetBase):
    pass

class AssetUpdate(BaseModel):
    type: Optional[str] = None
    model: Optional[str] = None
    vendor: Optional[str] = None
    department: Optional[str] = None
    risk_level: Optional[float] = None

class Asset(AssetBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    model_config = {
        "from_attributes": True
    }