# security_scanner_api_router.py
"""
Complete API Router for Security Vulnerability Scanner
Provides comprehensive REST endpoints for device vulnerability scanning


from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import asyncio
import os

from app.database import get_db
from app.services.security_vulnerability_scanner_service import VulnerabilityScanner
from app.models.asset import Asset
from app.models.cve import CVE
from app.models.cwe import CWE
from app.models.capec import CAPEC
from app.models.attack import Attack
from app.models.relations import AssetCVERelation, CVECWERelation, CWECAPECRelation, CAPECAttackRelation
from app.crud import asset as asset_crud
from app.crud import cve as cve_crud
from app.crud import cwe as cwe_crud
from app.crud import capec as capec_crud
from app.crud import attack as attack_crud
from app.utils.logger import logger

# Configure scanner
SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
NVD_API_KEY = os.getenv("NVD_API_KEY", "4a116d75-367e-4c9b-90de-904679b57060")
scanner = VulnerabilityScanner(NVD_API_KEY, SCRIPT_PATH)

router = APIRouter(prefix="/security", tags=["security-scanner"])


# ========== REQUEST/RESPONSE MODELS ==========

class CPESearchRequest(BaseModel):
    device_name: str

class CPEMatch(BaseModel):
    device_name: str
    vendor: str
    model: str
    cpe: str
    score: float

class CPESearchResponse(BaseModel):
    device_name: str
    matches: List[CPEMatch]
    total_matches: int

class ScanByCPERequest(BaseModel):
    cpe: str
    device_name: Optional[str] = None
    department: str = "Unknown"

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

class BatchScanRequest(BaseModel):
    devices: List[Dict[str, str]]  # [{"device_name": "...", "department": "..."}]

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


# ========== MAIN API ENDPOINTS ==========

@router.post("/cpe-search", response_model=CPESearchResponse)
async def search_cpe_matches(request: CPESearchRequest):
     
    API 1: Search for the 10 best CPE matches for a partial device name
    
    Args:
        request: Contains device_name (partial or full device name)
    
    Returns:
        Top 10 CPE matches with device details and match scores
     
    try:
        logger.info(f"Searching CPE matches for: {request.device_name}")
        
        # Use the enhanced CPE matcher to find matches
        cpe_matches = scanner.processor.find_matching_cpe(request.device_name, threshold=60)
        
        # Get detailed device information for each CPE match
        matches = []
        
        # Get the device data that was used for matching
        for i, cpe in enumerate(cpe_matches[:10]):  # Top 10 matches
            # Find the original device data that corresponds to this CPE
            matching_device = None
            for device in scanner.processor.cpes:
                if device.get('cpeName', '').replace("\\/", "/") == cpe:
                    matching_device = device
                    break
            
            if matching_device:
                # Calculate a score based on the position in results
                score = max(100 - (i * 10), 10)  # Decreasing score for each position
                
                match = CPEMatch(
                    device_name=matching_device.get('title', 'Unknown'),
                    vendor=matching_device.get('vendor', 'Unknown'),
                    model=matching_device.get('model', 'Unknown'),
                    cpe=cpe,
                    score=score
                )
                matches.append(match)
        
        logger.info(f"Found {len(matches)} CPE matches for {request.device_name}")
        
        return CPESearchResponse(
            device_name=request.device_name,
            matches=matches,
            total_matches=len(cpe_matches)
        )
        
    except Exception as e:
        logger.error(f"CPE search failed for {request.device_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"CPE search failed: {str(e)}")


@router.post("/scan-by-cpe", response_model=FullScanResponse)
async def scan_device_by_cpe(request: ScanByCPERequest, db: Session = Depends(get_db)):
     
    API 2: Scan device by CPE and return complete vulnerability data
    
    Args:
        request: Contains CPE, optional device_name, and department
        db: Database session
    
    Returns:
        Complete vulnerability information including Device, CVEs, CWEs, CAPECs, and ATT&CK data
     
    import time
    start_time = time.time()
    
    try:
        logger.info(f"Starting scan by CPE: {request.cpe}")
        
        # Extract device name from CPE if not provided
        device_name = request.device_name
        if not device_name:
            # Parse device name from CPE
            cpe_parts = request.cpe.split(":")
            if len(cpe_parts) >= 5:
                vendor = cpe_parts[3].replace("_", " ").title()
                model = cpe_parts[4].replace("_", " ")
                device_name = f"{vendor} {model}".strip()
            else:
                device_name = "Unknown Device"
        
        # Create a mock scanner request and run the scan
        scan_results = await scanner.scan_device(
            device_name=device_name,
            department=request.department,
            db_session=db
        )
        
        scan_time = time.time() - start_time
        
        if not scan_results['success']:
            return FullScanResponse(
                success=False,
                error_message=scan_results.get('error_message', 'Scan failed'),
                scan_time=scan_time,
                device=None,
                cves=[],
                cwes=[],
                capecs=[],
                attacks=[],
                statistics={"cves": 0, "cwes": 0, "capecs": 0, "attacks": 0}
            )
        
        # Find the created/updated asset
        assets = asset_crud.get_assets(db, skip=0, limit=1000)
        asset = None
        for a in assets:
            if a.name == device_name or (device_name in a.name or a.name in device_name):
                asset = a
                break
        
        if not asset:
            # If no asset found, create a minimal response
            return FullScanResponse(
                success=True,
                error_message=None,
                scan_time=scan_time,
                device=None,
                cves=[],
                cwes=[],
                capecs=[],
                attacks=[],
                statistics={"cves": 0, "cwes": 0, "capecs": 0, "attacks": 0}
            )
        
        # Get all related data
        cves = cve_crud.get_cves_by_asset_id(db, asset.id)
        
        all_cwes = []
        all_capecs = []
        all_attacks = []
        
        # Get CWEs for all CVEs
        for cve in cves:
            cwes = cwe_crud.get_cwes_by_cve_id(db, cve.id)
            all_cwes.extend(cwes)
            
            # Get CAPECs for each CWE
            for cwe in cwes:
                capecs = capec_crud.get_capecs_by_cwe_id(db, cwe.id)
                all_capecs.extend(capecs)
                
                # Get ATT&CK techniques for each CAPEC
                for capec in capecs:
                    attacks = attack_crud.get_attacks_by_capec_id(db, capec.id)
                    all_attacks.extend(attacks)
        
        # Remove duplicates
        unique_cwes = list({cwe.id: cwe for cwe in all_cwes}.values())
        unique_capecs = list({capec.id: capec for capec in all_capecs}.values())
        unique_attacks = list({attack.id: attack for attack in all_attacks}.values())
        
        # Convert to response models
        device_info = AssetInfo(
            id=asset.id,
            name=asset.name,
            vendor=asset.vendor or "Unknown",
            model=asset.model or "Unknown",
            version=asset.version or "Unknown",
            type=asset.type or "Unknown",
            department=asset.department or "Unknown",
            description=asset.description or "",
            risk_level=asset.risk_level or 0.0
        )
        
        cve_infos = [
            CVEInfo(
                id=cve.id,
                cve_id=cve.cve_id,
                description=cve.description,
                cvss=cve.cvss or 0.0,
                risk_level=cve.risk_level or 0.0,
                epss=cve.epss or 0.0,
                impact_score=cve.impact_score or 0.0,
                exploitability_score=cve.exploitability_score or 0.0
            ) for cve in cves
        ]
        
        cwe_infos = [
            CWEInfo(
                id=cwe.id,
                cwe_id=cwe.cwe_id,
                name=cwe.name,
                description=cwe.description
            ) for cwe in unique_cwes
        ]
        
        capec_infos = [
            CAPECInfo(
                id=capec.id,
                capec_id=capec.capec_id,
                name=capec.name,
                description=capec.description,
                typical_severity=capec.typical_severity or "Unknown",
                likelihood_of_attack=capec.likelihood_of_attack or "Unknown"
            ) for capec in unique_capecs
        ]
        
        attack_infos = [
            AttackInfo(
                id=attack.id,
                technique_id=attack.technique_id,
                external_id=attack.external_id,
                name=attack.name,
                description=attack.description,
                url=attack.url,
                tactics=attack.tactics,
                platforms=attack.platforms,
                data_sources=attack.data_sources,
                detection=attack.detection,
                permissions_required=attack.permissions_required
            ) for attack in unique_attacks
        ]
        
        statistics = {
            "cves": len(cves),
            "cwes": len(unique_cwes),
            "capecs": len(unique_capecs),
            "attacks": len(unique_attacks)
        }
        
        logger.info(f"Scan completed for CPE {request.cpe}: Found {statistics}")
        
        return FullScanResponse(
            success=True,
            error_message=None,
            scan_time=scan_time,
            device=device_info,
            cves=cve_infos,
            cwes=cwe_infos,
            capecs=capec_infos,
            attacks=attack_infos,
            statistics=statistics
        )
        
    except Exception as e:
        logger.error(f"Scan by CPE failed: {str(e)}")
        return FullScanResponse(
            success=False,
            error_message=str(e),
            scan_time=time.time() - start_time,
            device=None,
            cves=[],
            cwes=[],
            capecs=[],
            attacks=[],
            statistics={"cves": 0, "cwes": 0, "capecs": 0, "attacks": 0}
        )


# ========== ADDITIONAL MANAGEMENT ENDPOINTS ==========

@router.get("/devices", response_model=DeviceListResponse)
async def get_scanned_devices(
    page: int = 1,
    per_page: int = 50,
    department: Optional[str] = None,
    risk_level_min: Optional[float] = None,
    risk_level_max: Optional[float] = None,
    vendor: Optional[str] = None,
    sort_by: str = "risk_level",
    sort_order: str = "desc",
    db: Session = Depends(get_db)
):
     
    Get paginated list of scanned devices with filtering and sorting
     
    try:
        skip = (page - 1) * per_page
        
        query = db.query(Asset)
        
        # Apply filters
        if department:
            query = query.filter(Asset.department.ilike(f"%{department}%"))
        if risk_level_min is not None:
            query = query.filter(Asset.risk_level >= risk_level_min)
        if risk_level_max is not None:
            query = query.filter(Asset.risk_level <= risk_level_max)
        if vendor:
            query = query.filter(Asset.vendor.ilike(f"%{vendor}%"))
        
        # Apply sorting
        if sort_by == "risk_level":
            if sort_order == "desc":
                query = query.order_by(desc(Asset.risk_level))
            else:
                query = query.order_by(Asset.risk_level)
        elif sort_by == "name":
            if sort_order == "desc":
                query = query.order_by(desc(Asset.name))
            else:
                query = query.order_by(Asset.name)
        
        total = query.count()
        assets = query.offset(skip).limit(per_page).all()
        
        device_infos = [
            AssetInfo(
                id=asset.id,
                name=asset.name,
                vendor=asset.vendor or "Unknown",
                model=asset.model or "Unknown",
                version=asset.version or "Unknown",
                type=asset.type or "Unknown",
                department=asset.department or "Unknown",
                description=asset.description or "",
                risk_level=asset.risk_level or 0.0
            ) for asset in assets
        ]
        
        return DeviceListResponse(
            devices=device_infos,
            total=total,
            page=page,
            per_page=per_page
        )
        
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving devices")


@router.get("/devices/{asset_id}")
async def get_device_details(asset_id: int, db: Session = Depends(get_db)):
     
    Get detailed information for a specific device
     
    try:
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Get all related data (similar to scan-by-cpe response)
        cves = cve_crud.get_cves_by_asset_id(db, asset_id)
        
        all_cwes = []
        all_capecs = []
        all_attacks = []
        
        for cve in cves:
            cwes = cwe_crud.get_cwes_by_cve_id(db, cve.id)
            all_cwes.extend(cwes)
            
            for cwe in cwes:
                capecs = capec_crud.get_capecs_by_cwe_id(db, cwe.id)
                all_capecs.extend(capecs)
                
                for capec in capecs:
                    attacks = attack_crud.get_attacks_by_capec_id(db, capec.id)
                    all_attacks.extend(attacks)
        
        # Remove duplicates
        unique_cwes = list({cwe.id: cwe for cwe in all_cwes}.values())
        unique_capecs = list({capec.id: capec for capec in all_capecs}.values())
        unique_attacks = list({attack.id: attack for attack in all_attacks}.values())
        
        return {
            "device": AssetInfo(
                id=asset.id,
                name=asset.name,
                vendor=asset.vendor or "Unknown",
                model=asset.model or "Unknown",
                version=asset.version or "Unknown",
                type=asset.type or "Unknown",
                department=asset.department or "Unknown",
                description=asset.description or "",
                risk_level=asset.risk_level or 0.0
            ),
            "vulnerabilities": {
                "cves": [CVEInfo(
                    id=cve.id,
                    cve_id=cve.cve_id,
                    description=cve.description,
                    cvss=cve.cvss or 0.0,
                    risk_level=cve.risk_level or 0.0,
                    epss=cve.epss or 0.0,
                    impact_score=cve.impact_score or 0.0,
                    exploitability_score=cve.exploitability_score or 0.0
                ) for cve in cves],
                "cwes": [CWEInfo(
                    id=cwe.id,
                    cwe_id=cwe.cwe_id,
                    name=cwe.name,
                    description=cwe.description
                ) for cwe in unique_cwes],
                "capecs": [CAPECInfo(
                    id=capec.id,
                    capec_id=capec.capec_id,
                    name=capec.name,
                    description=capec.description,
                    typical_severity=capec.typical_severity or "Unknown",
                    likelihood_of_attack=capec.likelihood_of_attack or "Unknown"
                ) for capec in unique_capecs],
                "attacks": [AttackInfo(
                    id=attack.id,
                    technique_id=attack.technique_id,
                    external_id=attack.external_id,
                    name=attack.name,
                    description=attack.description,
                    url=attack.url,
                    tactics=attack.tactics,
                    platforms=attack.platforms,
                    data_sources=attack.data_sources,
                    detection=attack.detection,
                    permissions_required=attack.permissions_required
                ) for attack in unique_attacks]
            },
            "statistics": {
                "total_cves": len(cves),
                "total_cwes": len(unique_cwes),
                "total_capecs": len(unique_capecs),
                "total_attacks": len(unique_attacks)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device details: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving device details")


@router.post("/batch-scan")
async def batch_scan_devices(
    request: BatchScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
     
    Batch scan multiple devices in the background
     
    try:
        def run_batch_scan():
            async def batch_scan_async():
                tasks = []
                for device in request.devices:
                    task = scanner.scan_device(
                        device_name=device.get("device_name", ""),
                        department=device.get("department", "Unknown"),
                        db_session=db
                    )
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Log results
                for i, result in enumerate(results):
                    device_name = request.devices[i].get("device_name", "Unknown")
                    if isinstance(result, Exception):
                        logger.error(f"Device {device_name} scan failed: {result}")
                    else:
                        logger.info(f"Device {device_name} scan completed: {result.get('success', False)}")
            
            asyncio.run(batch_scan_async())
        
        background_tasks.add_task(run_batch_scan)
        
        return {
            "message": f"Batch scan started for {len(request.devices)} devices",
            "devices": [d.get("device_name", "Unknown") for d in request.devices],
            "status": "processing"
        }
        
    except Exception as e:
        logger.error(f"Batch scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Batch scan failed: {str(e)}")


@router.get("/stats", response_model=SecurityStatsResponse)
async def get_security_statistics(db: Session = Depends(get_db)):
     
    Get comprehensive security statistics for dashboard
     
    try:
        total_assets = db.query(Asset).count()
        vulnerable_assets = db.query(Asset).filter(Asset.risk_level > 0).count()
        total_cves = db.query(CVE).count()
        total_cwes = db.query(CWE).count()
        total_capecs = db.query(CAPEC).count()
        total_attacks = db.query(Attack).count()
        
        # Risk level statistics
        avg_risk_result = db.query(func.avg(Asset.risk_level)).scalar()
        avg_risk_level = float(avg_risk_result) if avg_risk_result else 0.0
        
        high_risk_assets = db.query(Asset).filter(Asset.risk_level > 50).count()
        critical_risk_assets = db.query(Asset).filter(Asset.risk_level > 80).count()
        
        # Top vendors by risk
        top_vendors = db.query(
            Asset.vendor,
            func.avg(Asset.risk_level).label('avg_risk'),
            func.count(Asset.id).label('count')
        ).group_by(Asset.vendor).having(func.count(Asset.id) > 0).order_by(desc('avg_risk')).limit(5).all()
        
        top_vendors_by_risk = [
            {
                "vendor": vendor or "Unknown",
                "average_risk": float(avg_risk),
                "device_count": count
            } for vendor, avg_risk, count in top_vendors
        ]
        
        # Recent scans (approximate - assets with risk_level > 0)
        recent_scans = vulnerable_assets
        
        return SecurityStatsResponse(
            total_assets=total_assets,
            vulnerable_assets=vulnerable_assets,
            total_cves=total_cves,
            total_cwes=total_cwes,
            total_capecs=total_capecs,
            total_attacks=total_attacks,
            average_risk_level=avg_risk_level,
            high_risk_assets=high_risk_assets,
            critical_risk_assets=critical_risk_assets,
            vulnerability_coverage=(vulnerable_assets / total_assets * 100) if total_assets > 0 else 0,
            top_vendors_by_risk=top_vendors_by_risk,
            recent_scans=recent_scans
        )
        
    except Exception as e:
        logger.error(f"Error getting security stats: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving security statistics")


@router.delete("/devices/{asset_id}")
async def delete_device(asset_id: int, db: Session = Depends(get_db)):
     
    Delete a device and all its associated data
     
    try:
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Device not found")
        
        device_info = f"{asset.vendor} {asset.model}"
        
        # Delete all relations (handled by cascade in models)
        deleted = asset_crud.delete_asset(db, asset_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return {
            "message": f"Device {device_info} deleted successfully",
            "asset_id": asset_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        raise HTTPException(status_code=500, detail="Error deleting device")


@router.get("/health")
async def health_check():
     
    Health check endpoint
     
    return {
        "status": "healthy",
        "service": "security-scanner",
        "scanner_initialized": scanner is not None,
        "components": {
            "database": "connected",
            "nvd_api": "configured",
            "cpe_matcher": "ready"
        }
    }


# ========== SEPARATE CRUD-BASED ROUTERS ==========

# assets.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.schemas.asset import Asset, AssetCreate, AssetUpdate
from app.crud import asset as asset_crud
from app.utils.logger import logger

assets_router = APIRouter(prefix="/assets", tags=["assets"])

@assets_router.get("/", response_model=List[Asset])
async def get_assets(
    skip: int = 0, 
    limit: int = 100, 
    department: Optional[str] = None,
    db: Session = Depends(get_db)
):
     Get all assets with pagination and optional filtering 
    try:
        if department:
            # If department filter is needed, implement in CRUD
            assets = db.query(asset_crud.Asset).filter(
                asset_crud.Asset.department.ilike(f"%{department}%")
            ).offset(skip).limit(limit).all()
        else:
            assets = asset_crud.get_assets(db, skip=skip, limit=limit)
        return assets
    except Exception as e:
        logger.error(f"Error getting assets: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@assets_router.get("/{asset_id}", response_model=Asset)
async def get_asset(asset_id: int, db: Session = Depends(get_db)):
     Get specific asset by ID 
    try:
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        return asset
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@assets_router.post("/", response_model=Asset)
async def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
     Create a new asset 
    try:
        return asset_crud.create_asset(db, asset)
    except Exception as e:
        logger.error(f"Error creating asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@assets_router.put("/{asset_id}", response_model=Asset)
async def update_asset(asset_id: int, asset: AssetUpdate, db: Session = Depends(get_db)):
     Update asset information 
    try:
        updated_asset = asset_crud.update_asset(db, asset_id, asset)
        if not updated_asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        return updated_asset
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@assets_router.delete("/{asset_id}")
async def delete_asset(asset_id: int, db: Session = Depends(get_db)):
     Delete asset 
    try:
        deleted = asset_crud.delete_asset(db, asset_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Asset not found")
        return {"message": "Asset deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# cves.py
cves_router = APIRouter(prefix="/cves", tags=["cves"])

@cves_router.get("/{cve_id}", response_model=CVEInfo)
async def get_cve(cve_id: int, db: Session = Depends(get_db)):
     Get specific CVE by ID 
    try:
        cve = cve_crud.get_cve(db, cve_id)
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        return CVEInfo(
            id=cve.id,
            cve_id=cve.cve_id,
            description=cve.description,
            cvss=cve.cvss or 0.0,
            risk_level=cve.risk_level or 0.0,
            epss=cve.epss or 0.0,
            impact_score=cve.impact_score or 0.0,
            exploitability_score=cve.exploitability_score or 0.0
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CVE: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@cves_router.get("/by-cve-id/{cve_id}")
async def get_cve_by_cve_id(cve_id: str, db: Session = Depends(get_db)):
     Get CVE by CVE identifier (e.g., CVE-2023-1234) 
    try:
        cve = cve_crud.get_cve_by_cve_id(db, cve_id)
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        return CVEInfo(
            id=cve.id,
            cve_id=cve.cve_id,
            description=cve.description,
            cvss=cve.cvss or 0.0,
            risk_level=cve.risk_level or 0.0,
            epss=cve.epss or 0.0,
            impact_score=cve.impact_score or 0.0,
            exploitability_score=cve.exploitability_score or 0.0
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CVE by CVE ID: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@cves_router.get("/asset/{asset_id}")
async def get_cves_by_asset(asset_id: int, db: Session = Depends(get_db)):
     Get all CVEs associated with an asset 
    try:
        cves = cve_crud.get_cves_by_asset_id(db, asset_id)
        
        return [
            CVEInfo(
                id=cve.id,
                cve_id=cve.cve_id,
                description=cve.description,
                cvss=cve.cvss or 0.0,
                risk_level=cve.risk_level or 0.0,
                epss=cve.epss or 0.0,
                impact_score=cve.impact_score or 0.0,
                exploitability_score=cve.exploitability_score or 0.0
            ) for cve in cves
        ]
    except Exception as e:
        logger.error(f"Error getting CVEs for asset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# cwes.py
cwes_router = APIRouter(prefix="/cwes", tags=["cwes"])

@cwes_router.get("/{cwe_id}", response_model=CWEInfo)
async def get_cwe(cwe_id: int, db: Session = Depends(get_db)):
     Get specific CWE by ID 
    try:
        cwe = cwe_crud.get_cwe(db, cwe_id)
        if not cwe:
            raise HTTPException(status_code=404, detail="CWE not found")
        
        return CWEInfo(
            id=cwe.id,
            cwe_id=cwe.cwe_id,
            name=cwe.name,
            description=cwe.description
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CWE: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@cwes_router.get("/by-cwe-id/{cwe_id}")
async def get_cwe_by_cwe_id(cwe_id: str, db: Session = Depends(get_db)):
     Get CWE by CWE identifier (e.g., CWE-79) 
    try:
        cwe = cwe_crud.get_cwe_by_cwe_id(db, cwe_id)
        if not cwe:
            raise HTTPException(status_code=404, detail="CWE not found")
        
        return CWEInfo(
            id=cwe.id,
            cwe_id=cwe.cwe_id,
            name=cwe.name,
            description=cwe.description
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CWE by CWE ID: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@cwes_router.get("/cve/{cve_id}")
async def get_cwes_by_cve(cve_id: int, db: Session = Depends(get_db)):
     Get all CWEs associated with a CVE 
    try:
        cwes = cwe_crud.get_cwes_by_cve_id(db, cve_id)
        
        return [
            CWEInfo(
                id=cwe.id,
                cwe_id=cwe.cwe_id,
                name=cwe.name,
                description=cwe.description
            ) for cwe in cwes
        ]
    except Exception as e:
        logger.error(f"Error getting CWEs for CVE: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# capecs.py
capecs_router = APIRouter(prefix="/capecs", tags=["capecs"])

@capecs_router.get("/{capec_id}", response_model=CAPECInfo)
async def get_capec(capec_id: int, db: Session = Depends(get_db)):
     Get specific CAPEC by ID 
    try:
        capec = capec_crud.get_capec(db, capec_id)
        if not capec:
            raise HTTPException(status_code=404, detail="CAPEC not found")
        
        return CAPECInfo(
            id=capec.id,
            capec_id=capec.capec_id,
            name=capec.name,
            description=capec.description,
            typical_severity=capec.typical_severity or "Unknown",
            likelihood_of_attack=capec.likelihood_of_attack or "Unknown"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CAPEC: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@capecs_router.get("/by-capec-id/{capec_id}")
async def get_capec_by_capec_id(capec_id: str, db: Session = Depends(get_db)):
     Get CAPEC by CAPEC identifier (e.g., CAPEC-123) 
    try:
        capec = capec_crud.get_capec_by_capec_id(db, capec_id)
        if not capec:
            raise HTTPException(status_code=404, detail="CAPEC not found")
        
        return CAPECInfo(
            id=capec.id,
            capec_id=capec.capec_id,
            name=capec.name,
            description=capec.description,
            typical_severity=capec.typical_severity or "Unknown",
            likelihood_of_attack=capec.likelihood_of_attack or "Unknown"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CAPEC by CAPEC ID: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@capecs_router.get("/cwe/{cwe_id}")
async def get_capecs_by_cwe(cwe_id: int, db: Session = Depends(get_db)):
     Get all CAPECs associated with a CWE 
    try:
        capecs = capec_crud.get_capecs_by_cwe_id(db, cwe_id)
        
        return [
            CAPECInfo(
                id=capec.id,
                capec_id=capec.capec_id,
                name=capec.name,
                description=capec.description,
                typical_severity=capec.typical_severity or "Unknown",
                likelihood_of_attack=capec.likelihood_of_attack or "Unknown"
            ) for capec in capecs
        ]
    except Exception as e:
        logger.error(f"Error getting CAPECs for CWE: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# attacks.py
attacks_router = APIRouter(prefix="/attacks", tags=["attacks"])

@attacks_router.get("/{attack_id}", response_model=AttackInfo)
async def get_attack(attack_id: int, db: Session = Depends(get_db)):
     Get specific ATT&CK technique by ID 
    try:
        attack = attack_crud.get_attack(db, attack_id)
        if not attack:
            raise HTTPException(status_code=404, detail="ATT&CK technique not found")
        
        return AttackInfo(
            id=attack.id,
            technique_id=attack.technique_id,
            external_id=attack.external_id,
            name=attack.name,
            description=attack.description,
            url=attack.url,
            tactics=attack.tactics,
            platforms=attack.platforms,
            data_sources=attack.data_sources,
            detection=attack.detection,
            permissions_required=attack.permissions_required
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting ATT&CK technique: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@attacks_router.get("/by-technique-id/{technique_id}")
async def get_attack_by_technique_id(technique_id: str, db: Session = Depends(get_db)):
     Get ATT&CK technique by technique ID (e.g., T1234) 
    try:
        attack = attack_crud.get_attack_by_technique_id(db, technique_id)
        if not attack:
            raise HTTPException(status_code=404, detail="ATT&CK technique not found")
        
        return AttackInfo(
            id=attack.id,
            technique_id=attack.technique_id,
            external_id=attack.external_id,
            name=attack.name,
            description=attack.description,
            url=attack.url,
            tactics=attack.tactics,
            platforms=attack.platforms,
            data_sources=attack.data_sources,
            detection=attack.detection,
            permissions_required=attack.permissions_required
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting ATT&CK technique by technique ID: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@attacks_router.get("/capec/{capec_id}")
async def get_attacks_by_capec(capec_id: int, db: Session = Depends(get_db)):
     Get all ATT&CK techniques associated with a CAPEC 
    try:
        attacks = attack_crud.get_attacks_by_capec_id(db, capec_id)
        
        return [
            AttackInfo(
                id=attack.id,
                technique_id=attack.technique_id,
                external_id=attack.external_id,
                name=attack.name,
                description=attack.description,
                url=attack.url,
                tactics=attack.tactics,
                platforms=attack.platforms,
                data_sources=attack.data_sources,
                detection=attack.detection,
                permissions_required=attack.permissions_required
            ) for attack in attacks
        ]
    except Exception as e:
        logger.error(f"Error getting ATT&CK techniques for CAPEC: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ========== REPORTS AND ANALYTICS ENDPOINTS ==========

reports_router = APIRouter(prefix="/reports", tags=["reports"])

@reports_router.get("/risk-summary")
async def get_risk_summary(db: Session = Depends(get_db)):
     Get risk summary report 
    try:
        from sqlalchemy import text
        
        # Risk distribution
        risk_distribution = db.execute(text(
            SELECT 
                CASE 
                    WHEN risk_level = 0 THEN 'No Risk'
                    WHEN risk_level <= 25 THEN 'Low'
                    WHEN risk_level <= 50 THEN 'Medium'
                    WHEN risk_level <= 75 THEN 'High'
                    ELSE 'Critical'
                END as risk_category,
                COUNT(*) as count
            FROM assets
            GROUP BY risk_category
         )).fetchall()
        
        # Department risk analysis
        department_risks = db.execute(text(
            SELECT 
                department,
                COUNT(*) as total_devices,
                AVG(risk_level) as avg_risk,
                MAX(risk_level) as max_risk
            FROM assets
            WHERE department IS NOT NULL
            GROUP BY department
            ORDER BY avg_risk DESC
        )).fetchall()
        
        # Top vulnerabilities
        top_cves = db.execute(text(
            SELECT 
                c.cve_id,
                c.description,
                c.cvss,
                COUNT(acr.asset_id) as affected_devices
            FROM cves c
            JOIN asset_cve_relations acr ON c.id = acr.cve_id
            GROUP BY c.id, c.cve_id, c.description, c.cvss
            ORDER BY affected_devices DESC, c.cvss DESC
            LIMIT 10
         )).fetchall()
        
        return {
            "risk_distribution": [
                {"category": row[0], "count": row[1]} for row in risk_distribution
            ],
            "department_analysis": [
                {
                    "department": row[0],
                    "total_devices": row[1],
                    "average_risk": float(row[2]) if row[2] else 0.0,
                    "max_risk": float(row[3]) if row[3] else 0.0
                } for row in department_risks
            ],
            "top_vulnerabilities": [
                {
                    "cve_id": row[0],
                    "description": row[1][:100] + "..." if len(row[1]) > 100 else row[1],
                    "cvss": float(row[2]) if row[2] else 0.0,
                    "affected_devices": row[3]
                } for row in top_cves
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting risk summary: {e}")
        raise HTTPException(status_code=500, detail="Error generating risk summary")

@reports_router.get("/vulnerability-trends")
async def get_vulnerability_trends(db: Session = Depends(get_db)):
     Get vulnerability trends over time 
    try:
        from sqlalchemy import text
        
        # CVE trends by year
        cve_trends = db.execute(text( 
            SELECT 
                SUBSTRING(cve_id, 5, 4) as year,
                COUNT(*) as count
            FROM cves
            WHERE cve_id LIKE 'CVE-%'
            GROUP BY year
            ORDER BY year DESC
            LIMIT 10
         )).fetchall()
        
        # CVSS score distribution
        cvss_distribution = db.execute(text( 
            SELECT 
                CASE 
                    WHEN cvss = 0 THEN 'Not Rated'
                    WHEN cvss < 4 THEN 'Low (0.0-3.9)'
                    WHEN cvss < 7 THEN 'Medium (4.0-6.9)'
                    WHEN cvss < 9 THEN 'High (7.0-8.9)'
                    ELSE 'Critical (9.0-10.0)'
                END as severity,
                COUNT(*) as count
            FROM cves
            GROUP BY severity
         )).fetchall()
        
        return {
            "cve_trends_by_year": [
                {"year": row[0], "count": row[1]} for row in cve_trends
            ],
            "severity_distribution": [
                {"severity": row[0], "count": row[1]} for row in cvss_distribution
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting vulnerability trends: {e}")
        raise HTTPException(status_code=500, detail="Error generating vulnerability trends")

@reports_router.get("/attack-surface")
async def get_attack_surface(db: Session = Depends(get_db)):
     Get attack surface analysis 
    try:
        from sqlalchemy import text
        
        # Top attack techniques
        top_attacks = db.execute(text( 
            SELECT 
                a.name,
                a.tactics,
                COUNT(DISTINCT acr.asset_id) as potential_targets
            FROM attacks a
            JOIN capec_attack_relations car ON a.id = car.attack_id
            JOIN cwe_capec_relations ccr ON car.capec_id = ccr.capec_id
            JOIN cve_cwe_relations cvr ON ccr.cwe_id = cvr.cwe_id
            JOIN asset_cve_relations acr ON cvr.cve_id = acr.cve_id
            GROUP BY a.id, a.name, a.tactics
            ORDER BY potential_targets DESC
            LIMIT 15
         )).fetchall()
        
        # Most vulnerable vendors
        vulnerable_vendors = db.execute(text( 
            SELECT 
                vendor,
                COUNT(*) as device_count,
                AVG(risk_level) as avg_risk,
                COUNT(DISTINCT acr.cve_id) as unique_vulnerabilities
            FROM assets a
            LEFT JOIN asset_cve_relations acr ON a.id = acr.asset_id
            WHERE vendor IS NOT NULL AND vendor != 'Unknown'
            GROUP BY vendor
            HAVING COUNT(DISTINCT acr.cve_id) > 0
            ORDER BY avg_risk DESC, unique_vulnerabilities DESC
            LIMIT 10
         )).fetchall()
        
        return {
            "top_attack_techniques": [
                {
                    "technique": row[0],
                    "tactics": row[1],
                    "potential_targets": row[2]
                } for row in top_attacks
            ],
            "vulnerable_vendors": [
                {
                    "vendor": row[0],
                    "device_count": row[1],
                    "average_risk": float(row[2]) if row[2] else 0.0,
                    "unique_vulnerabilities": row[3]
                } for row in vulnerable_vendors
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting attack surface: {e}")
        raise HTTPException(status_code=500, detail="Error generating attack surface analysis")


# ========== MAIN ROUTER COMBINING ALL ENDPOINTS ==========

def create_main_router():
     Create the main router combining all sub-routers 
    from fastapi import APIRouter
    
    main_router = APIRouter()
    
    # Include all routers
    main_router.include_router(router)  # Security scanner main router
    main_router.include_router(assets_router)
    main_router.include_router(cves_router)
    main_router.include_router(cwes_router)
    main_router.include_router(capecs_router)
    main_router.include_router(attacks_router)
    main_router.include_router(reports_router)
    
    return main_router


# ========== USAGE EXAMPLE FOR MAIN APP ==========


To use these routers in your main FastAPI application:

from fastapi import FastAPI
from your_complete_routers import create_main_router

app = FastAPI(title="Security Vulnerability Scanner API")
app.include_router(create_main_router())

This provides you with the following complete endpoints:

MAIN FUNCTIONALITY:
POST /security/cpe-search          # API 1: Search CPE matches
POST /security/scan-by-cpe         # API 2: Full scan by CPE
POST /security/batch-scan          # Batch scanning
GET  /security/devices             # List devices with filtering
GET  /security/devices/{id}        # Get device details
GET  /security/stats               # Security statistics
DELETE /security/devices/{id}      # Delete device
GET  /security/health              # Health check

CRUD OPERATIONS:
GET    /assets/                    # List assets
GET    /assets/{id}               # Get asset
POST   /assets/                   # Create asset
PUT    /assets/{id}               # Update asset
DELETE /assets/{id}               # Delete asset

GET    /cves/{id}                 # Get CVE by ID
GET    /cves/by-cve-id/{cve_id}   # Get CVE by CVE-ID
GET    /cves/asset/{asset_id}     # Get CVEs for asset

GET    /cwes/{id}                 # Get CWE by ID
GET    /cwes/by-cwe-id/{cwe_id}   # Get CWE by CWE-ID
GET    /cwes/cve/{cve_id}         # Get CWEs for CVE

GET    /capecs/{id}               # Get CAPEC by ID
GET    /capecs/by-capec-id/{capec_id} # Get CAPEC by CAPEC-ID
GET    /capecs/cwe/{cwe_id}       # Get CAPECs for CWE

GET    /attacks/{id}              # Get Attack by ID
GET    /attacks/by-technique-id/{technique_id} # Get Attack by technique ID
GET    /attacks/capec/{capec_id}  # Get Attacks for CAPEC

REPORTS & ANALYTICS:
GET    /reports/risk-summary      # Risk summary report
GET    /reports/vulnerability-trends # Vulnerability trends
GET    /reports/attack-surface    # Attack surface analysis
"""