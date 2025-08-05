from pydantic import BaseModel
from typing import List, Optional
from app.schemas.asset import Asset
from app.schemas.cve import CVE
from app.schemas.cwe import CWE
from app.schemas.capec import CAPEC
from app.schemas.attack import Attack

class AssetFullResponse(BaseModel):
    device: Asset
    cves: List[CVE]
    cwes: List[CWE]
    capecs: List[CAPEC]
    attacks: List[Attack]

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[dict] = None