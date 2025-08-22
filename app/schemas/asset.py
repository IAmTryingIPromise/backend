from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AssetBase(BaseModel):
    name: str
    type: str
    model: str
    vendor: str
    version: Optional[str] = None
    department: str
    description: Optional[str] = None
    risk_level: Optional[float] = None

class AssetCreate(AssetBase):
    pass

class AssetUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    model: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None
    department: Optional[str] = None
    description: Optional[str] = None
    risk_level: Optional[float] = None

class Asset(AssetBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    model_config = {
        "from_attributes": True
    }