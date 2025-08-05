from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class CVEBase(BaseModel):
    cve_id: str
    description: Optional[str] = None
    cvss: Optional[float] = None
    exploitability: Optional[float] = None
    impact: Optional[float] = None
    epss: Optional[float] = None
    risk_level: float = .0

class CVECreate(CVEBase):
    pass

class CVE(CVEBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True