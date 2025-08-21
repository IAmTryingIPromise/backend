# routers/security.py
"""
Main Security Vulnerability Scanner API Router
Core functionality for device vulnerability scanning
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import time
import os

from app.database import get_db
from app.services.security_vulnerability_scanner_service import VulnerabilityScanner
from app.crud import asset as asset_crud
from app.crud import cve as cve_crud
from app.crud import cwe as cwe_crud
from app.crud import capec as capec_crud
from app.crud import attack as attack_crud
from app.utils.logger import logger
from .schemas import (
    CPESearchRequest, CPESearchResponse, ScanByCPERequest, FullScanResponse,
    BatchScanRequest, DeviceListResponse, SecurityStatsResponse,
    AssetInfo, CVEInfo, CWEInfo, CAPECInfo, AttackInfo
)

# Configure scanner
SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
NVD_API_KEY = os.getenv("NVD_API_KEY", "4a116d75-367e-4c9b-90de-904679b57060")
scanner = VulnerabilityScanner(NVD_API_KEY, SCRIPT_PATH)

router = APIRouter(prefix="/security", tags=["security-scanner"])


@router.post("/cpe-search", response_model=CPESearchResponse)
async def search_cpe_matches(request: CPESearchRequest):
    """
    API 1: Search for the 10 best CPE matches for a partial device name
    """
    try:
        logger.info(f"Searching CPE matches for: {request.device_name}")
        
        cpe_matches = scanner.processor.find_matching_cpe(request.device_name, threshold=60)
        matches = []
        
        for i, cpe in enumerate(cpe_matches[:10]):
            matching_device = None
            for device in scanner.processor.cpes:
                if device.get('cpeName', '').replace("\\/", "/") == cpe:
                    matching_device = device
                    break
            
            if matching_device:
                score = max(100 - (i * 10), 10)
                matches.append({
                    "device_name": matching_device.get('title', 'Unknown'),
                    "vendor": matching_device.get('vendor', 'Unknown'),
                    "model": matching_device.get('model', 'Unknown'),
                    "cpe": cpe,
                    "score": score
                })
        
        logger.info(f"Found {len(matches)} CPE matches for {request.device_name}")
        
        return {
            "device_name": request.device_name,
            "matches": matches,
            "total_matches": len(cpe_matches)
        }
        
    except Exception as e:
        logger.error(f"CPE search failed for {request.device_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"CPE search failed: {str(e)}")


@router.post("/scan-by-cpe", response_model=FullScanResponse)
async def scan_device_by_cpe(request: ScanByCPERequest, db: Session = Depends(get_db)):
    """
    API 2: Scan device by CPE and return complete vulnerability data
    """
    start_time = time.time()
    
    try:
        logger.info(f"Starting scan by CPE: {request.cpe}")
        
        # Extract device name from CPE if not provided
        device_name = request.device_name
        if not device_name:
            cpe_parts = request.cpe.split(":")
            if len(cpe_parts) >= 5:
                vendor = cpe_parts[3].replace("_", " ").title()
                model = cpe_parts[4].replace("_", " ")
                device_name = f"{vendor} {model}".strip()
            else:
                device_name = "Unknown Device"
        
        # Run the scan
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
                cves=[], cwes=[], capecs=[], attacks=[],
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
            return FullScanResponse(
                success=True, error_message=None, scan_time=scan_time,
                device=None, cves=[], cwes=[], capecs=[], attacks=[],
                statistics={"cves": 0, "cwes": 0, "capecs": 0, "attacks": 0}
            )
        
        # Get all related data and build response
        response_data = _build_full_scan_response(db, asset, scan_time)
        return response_data
        
    except Exception as e:
        logger.error(f"Scan by CPE failed: {str(e)}")
        return FullScanResponse(
            success=False, error_message=str(e), scan_time=time.time() - start_time,
            device=None, cves=[], cwes=[], capecs=[], attacks=[],
            statistics={"cves": 0, "cwes": 0, "capecs": 0, "attacks": 0}
        )


@router.get("/devices", response_model=DeviceListResponse)
async def get_scanned_devices(
    page: int = 1, per_page: int = 50, department: Optional[str] = None,
    risk_level_min: Optional[float] = None, risk_level_max: Optional[float] = None,
    vendor: Optional[str] = None, sort_by: str = "risk_level", sort_order: str = "desc",
    db: Session = Depends(get_db)
):
    """
    API 3: Get paginated list of scanned devices with filtering and sorting
    """
    try:
        skip = (page - 1) * per_page
        query = db.query(asset_crud.Asset)
        
        # Apply filters
        if department:
            query = query.filter(asset_crud.Asset.department.ilike(f"%{department}%"))
        if risk_level_min is not None:
            query = query.filter(asset_crud.Asset.risk_level >= risk_level_min)
        if risk_level_max is not None:
            query = query.filter(asset_crud.Asset.risk_level <= risk_level_max)
        if vendor:
            query = query.filter(asset_crud.Asset.vendor.ilike(f"%{vendor}%"))
        
        # Apply sorting
        if sort_by == "risk_level":
            query = query.order_by(asset_crud.Asset.risk_level.desc() if sort_order == "desc" 
                                 else asset_crud.Asset.risk_level)
        elif sort_by == "name":
            query = query.order_by(asset_crud.Asset.name.desc() if sort_order == "desc" 
                                 else asset_crud.Asset.name)
        
        total = query.count()
        assets = query.offset(skip).limit(per_page).all()
        
        device_infos = [_convert_asset_to_info(asset) for asset in assets]
        
        return DeviceListResponse(
            devices=device_infos, total=total, page=page, per_page=per_page
        )
        
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving devices")


@router.get("/devices/{asset_id}")
async def get_device_details(asset_id: int, db: Session = Depends(get_db)):
    """
    API 4: Get detailed information for a specific device
    """
    try:
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Get all vulnerability data
        cves = cve_crud.get_cves_by_asset_id(db, asset_id)
        all_cwes, all_capecs, all_attacks = _get_related_vulnerability_data(db, cves)
        
        return {
            "device": _convert_asset_to_info(asset),
            "vulnerabilities": {
                "cves": [_convert_cve_to_info(cve) for cve in cves],
                "cwes": [_convert_cwe_to_info(cwe) for cwe in all_cwes],
                "capecs": [_convert_capec_to_info(capec) for capec in all_capecs],
                "attacks": [_convert_attack_to_info(attack) for attack in all_attacks]
            },
            "statistics": {
                "total_cves": len(cves),
                "total_cwes": len(all_cwes),
                "total_capecs": len(all_capecs),
                "total_attacks": len(all_attacks)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device details: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving device details")


@router.delete("/devices/{asset_id}")
async def delete_device(asset_id: int, db: Session = Depends(get_db)):
    """
    API 5: Delete a device and all its associated data
    """
    try:
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Device not found")
        
        device_info = f"{asset.vendor} {asset.model}"
        deleted = asset_crud.delete_asset(db, asset_id)
        
        if not deleted:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return {"message": f"Device {device_info} deleted successfully", "asset_id": asset_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        raise HTTPException(status_code=500, detail="Error deleting device")


@router.post("/refresh-device/{asset_id}")
async def refresh_device_scan(asset_id: int, db: Session = Depends(get_db)):
    """
    API 6: Refresh scan for existing device (re-run vulnerability scan)
    """
    try:
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Re-run scan for existing device
        scan_results = await scanner.scan_device(
            device_name=asset.name,
            department=asset.department or "Unknown",
            db_session=db
        )
        
        if not scan_results['success']:
            raise HTTPException(status_code=500, detail="Refresh scan failed")
        
        # Return updated device data
        response_data = _build_full_scan_response(db, asset, 0.0)
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing device scan: {e}")
        raise HTTPException(status_code=500, detail="Error refreshing device scan")


@router.get("/stats", response_model=SecurityStatsResponse)
async def get_security_statistics(db: Session = Depends(get_db)):
    """
    Get security statistics for dashboard
    """
    try:
        from sqlalchemy import func, desc
        from app.models.asset import Asset
        from app.models.cve import CVE
        from app.models.cwe import CWE
        from app.models.capec import CAPEC
        from app.models.attack import Attack
        
        total_assets = db.query(Asset).count()
        vulnerable_assets = db.query(Asset).filter(Asset.risk_level > 0).count()
        total_cves = db.query(CVE).count()
        total_cwes = db.query(CWE).count()
        total_capecs = db.query(CAPEC).count()
        total_attacks = db.query(Attack).count()
        
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
            {"vendor": vendor or "Unknown", "average_risk": float(avg_risk), "device_count": count}
            for vendor, avg_risk, count in top_vendors
        ]
        
        return SecurityStatsResponse(
            total_assets=total_assets, vulnerable_assets=vulnerable_assets,
            total_cves=total_cves, total_cwes=total_cwes, total_capecs=total_capecs,
            total_attacks=total_attacks, average_risk_level=avg_risk_level,
            high_risk_assets=high_risk_assets, critical_risk_assets=critical_risk_assets,
            vulnerability_coverage=(vulnerable_assets / total_assets * 100) if total_assets > 0 else 0,
            top_vendors_by_risk=top_vendors_by_risk, recent_scans=vulnerable_assets
        )
        
    except Exception as e:
        logger.error(f"Error getting security stats: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving security statistics")


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "security-scanner",
        "scanner_initialized": scanner is not None,
        "components": {"database": "connected", "nvd_api": "configured", "cpe_matcher": "ready"}
    }


# Helper functions
def _build_full_scan_response(db: Session, asset, scan_time: float) -> FullScanResponse:
    """Build complete scan response with all related vulnerability data"""
    cves = cve_crud.get_cves_by_asset_id(db, asset.id)
    all_cwes, all_capecs, all_attacks = _get_related_vulnerability_data(db, cves)
    
    return FullScanResponse(
        success=True, error_message=None, scan_time=scan_time,
        device=_convert_asset_to_info(asset),
        cves=[_convert_cve_to_info(cve) for cve in cves],
        cwes=[_convert_cwe_to_info(cwe) for cwe in all_cwes],
        capecs=[_convert_capec_to_info(capec) for capec in all_capecs],
        attacks=[_convert_attack_to_info(attack) for attack in all_attacks],
        statistics={"cves": len(cves), "cwes": len(all_cwes), "capecs": len(all_capecs), "attacks": len(all_attacks)}
    )


def _get_related_vulnerability_data(db: Session, cves):
    """Get all related CWEs, CAPECs, and ATT&CK techniques for given CVEs"""
    all_cwes, all_capecs, all_attacks = [], [], []
    
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
    
    return unique_cwes, unique_capecs, unique_attacks


def _convert_asset_to_info(asset) -> AssetInfo:
    """Convert Asset model to AssetInfo response model"""
    return AssetInfo(
        id=asset.id, name=asset.name, vendor=asset.vendor or "Unknown",
        model=asset.model or "Unknown", version=asset.version or "Unknown",
        type=asset.type or "Unknown", department=asset.department or "Unknown",
        description=asset.description or "", risk_level=asset.risk_level or 0.0
    )


def _convert_cve_to_info(cve) -> CVEInfo:
    """Convert CVE model to CVEInfo response model"""
    return CVEInfo(
        id=cve.id, cve_id=cve.cve_id, description=cve.description,
        cvss=cve.cvss or 0.0, risk_level=cve.risk_level or 0.0,
        epss=cve.epss or 0.0, impact_score=cve.impact_score or 0.0,
        exploitability_score=cve.exploitability_score or 0.0
    )


def _convert_cwe_to_info(cwe) -> CWEInfo:
    """Convert CWE model to CWEInfo response model"""
    return CWEInfo(id=cwe.id, cwe_id=cwe.cwe_id, name=cwe.name, description=cwe.description)


def _convert_capec_to_info(capec) -> CAPECInfo:
    """Convert CAPEC model to CAPECInfo response model"""
    return CAPECInfo(
        id=capec.id, capec_id=capec.capec_id, name=capec.name, description=capec.description,
        typical_severity=capec.typical_severity or "Unknown",
        likelihood_of_attack=capec.likelihood_of_attack or "Unknown"
    )


def _convert_attack_to_info(attack) -> AttackInfo:
    """Convert Attack model to AttackInfo response model"""
    return AttackInfo(
        id=attack.id, technique_id=attack.technique_id, external_id=attack.external_id,
        name=attack.name, description=attack.description, url=attack.url,
        tactics=attack.tactics, platforms=attack.platforms, data_sources=attack.data_sources,
        detection=attack.detection, permissions_required=attack.permissions_required
    )