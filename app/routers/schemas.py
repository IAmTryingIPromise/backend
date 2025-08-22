# routers/schemas.py
"""
Request and Response Schema Models for Security Scanner API
"""

from pydantic import BaseModel
from typing import List, Dict, Any, Optional


# ========== REQUEST MODELS ==========

class CPESearchRequest(BaseModel):
    device_name: str


class ScanByCPERequest(BaseModel):
    cpe: str
    device_name: Optional[str] = None
    department: str = "Unknown"


class BatchScanRequest(BaseModel):
    devices: List[Dict[str, str]]  # [{"device_name": "...", "department": "..."}]


# ========== RESPONSE DATA MODELS ==========

class CPEMatch(BaseModel):
    device_name: str
    vendor: str
    model: str
    cpe: str
    score: float


class AssetInfo(BaseModel):
    id: int
    name: str
    vendor: str
    model: str
    version: str
    type: str
    department: str
    description: str
    risk_level: float


class CVEInfo(BaseModel):
    id: int
    cve_id: str
    description: str
    cvss: float
    risk_level: float
    epss: float
    impact_score: float
    exploitability_score: float


class CWEInfo(BaseModel):
    id: int
    cwe_id: str
    name: str
    description: str


class CAPECInfo(BaseModel):
    id: int
    capec_id: str
    name: str
    description: str
    typical_severity: str
    likelihood_of_attack: str


class AttackInfo(BaseModel):
    id: int
    technique_id: str
    external_id: str
    name: str
    description: str
    url: Optional[str]
    tactics: Optional[str]
    platforms: Optional[str]
    data_sources: Optional[str]
    detection: Optional[str]
    permissions_required: Optional[str]


# ========== MAIN RESPONSE MODELS ==========

class CPESearchResponse(BaseModel):
    device_name: str
    matches: List[CPEMatch]
    total_matches: int


class FullScanResponse(BaseModel):
    success: bool
    error_message: Optional[str]
    scan_time: float
    device: Optional[AssetInfo]
    cves: List[CVEInfo]
    cwes: List[CWEInfo]
    capecs: List[CAPECInfo]
    attacks: List[AttackInfo]
    statistics: Dict[str, int]


class DeviceListResponse(BaseModel):
    devices: List[AssetInfo]
    total: int
    page: int
    per_page: int


class SecurityStatsResponse(BaseModel):
    total_assets: int
    vulnerable_assets: int
    total_cves: int
    total_cwes: int
    total_capecs: int
    total_attacks: int
    average_risk_level: float
    high_risk_assets: int
    critical_risk_assets: int
    vulnerability_coverage: float
    top_vendors_by_risk: List[Dict[str, Any]]
    recent_scans: int