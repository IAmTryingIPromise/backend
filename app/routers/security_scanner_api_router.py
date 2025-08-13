"""
API Router for Security Vulnerability Scanner
Provides REST endpoints for device vulnerability scanning
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func
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
from app.utils.logger import logger

# Configure scanner
SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
NVD_API_KEY = os.getenv("NVD_API_KEY", "4a116d75-367e-4c9b-90de-904679b57060")  # Replace with your actual key
scanner = VulnerabilityScanner(NVD_API_KEY, SCRIPT_PATH)

router = APIRouter(prefix="/security", tags=["security-scanner"])


class ScanRequest(BaseModel):
    device_name: str
    department: str = "Unknown"


class ScanResponse(BaseModel):
    device_name: str
    department: str
    cpe_matches: List[str]
    vulnerabilities_found: int
    cves_processed: int
    cwes_processed: int
    capecs_processed: int
    attacks_processed: int
    scan_time: float
    success: bool
    error_message: Optional[str] = None


class DeviceInfo(BaseModel):
    id: int
    vendor: str
    model: str
    type: str
    department: str
    risk_level: float


class VulnerabilityInfo(BaseModel):
    cve_id: str
    description: str
    cvss: float
    risk_level: float
    epss: float
    related_cwes: List[Dict[str, str]]


class DeviceVulnerabilityResponse(BaseModel):
    device: DeviceInfo
    vulnerabilities: List[VulnerabilityInfo]
    total_vulnerabilities: int


@router.post("/scan", response_model=ScanResponse)
async def scan_device(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Scan a device for vulnerabilities and store results in database
    
    This endpoint:
    1. Finds matching CPE for the device
    2. Fetches vulnerability data from NVD
    3. Processes CVE, CWE, CAPEC, and ATT&CK data
    4. Stores everything in the database with proper relationships
    
    Args:
        request: Device scanning request containing device name and department
        background_tasks: FastAPI background tasks for async processing
        db: Database session
    
    Returns:
        Scan results including statistics and any errors
    """
    try:
        logger.info(f"Starting scan for device: {request.device_name}")
        
        # Run the scan
        results = await scanner.scan_device(
            device_name=request.device_name,
            department=request.department,
            db_session=db
        )
        
        logger.info(f"Scan completed for {request.device_name}: {results['success']}")
        return ScanResponse(**results)
        
    except Exception as e:
        logger.error(f"Scan failed for {request.device_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan-batch")
async def scan_multiple_devices(
    devices: List[ScanRequest],
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Scan multiple devices in batch (asynchronously in background)
    
    Args:
        devices: List of devices to scan
        background_tasks: FastAPI background tasks
        db: Database session
    
    Returns:
        Acknowledgment that batch scan has started
    """
    def run_batch_scan():
        """Background task to process multiple devices"""
        async def batch_scan_async():
            tasks = []
            for device_request in devices:
                task = scanner.scan_device(
                    device_name=device_request.device_name,
                    department=device_request.department,
                    db_session=db
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Log results
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Device {devices[i].device_name} scan failed: {result}")
                else:
                    logger.info(f"Device {devices[i].device_name} scan completed: {result['success']}")
        
        # Run the async function in the background
        asyncio.run(batch_scan_async())
    
    background_tasks.add_task(run_batch_scan)
    
    return {
        "message": f"Batch scan started for {len(devices)} devices",
        "devices": [d.device_name for d in devices]
    }


@router.get("/devices", response_model=List[DeviceInfo])
async def get_scanned_devices(
    skip: int = 0,
    limit: int = 100,
    department: Optional[str] = None,
    risk_level_min: Optional[float] = None,
    db: Session = Depends(get_db)
):
    """
    Get list of scanned devices with their risk levels
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        department: Filter by department
        risk_level_min: Minimum risk level filter
        db: Database session
    
    Returns:
        List of devices with their information
    """
    try:
        # Use the existing CRUD function
        assets = asset_crud.get_assets(db, skip=skip, limit=limit)
        
        # Apply additional filters if needed
        if department or risk_level_min is not None:
            query = db.query(Asset)
            
            if department:
                query = query.filter(Asset.department == department)
            
            if risk_level_min is not None:
                query = query.filter(Asset.risk_level >= risk_level_min)
            
            assets = query.offset(skip).limit(limit).all()
        
        return [
            DeviceInfo(
                id=asset.id,
                vendor=asset.vendor or "Unknown",
                model=asset.model or "Unknown",
                type=asset.type or "Unknown",
                department=asset.department or "Unknown",
                risk_level=asset.risk_level or 0.0
            )
            for asset in assets
        ]
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving devices")


@router.get("/devices/{asset_id}/vulnerabilities", response_model=DeviceVulnerabilityResponse)
async def get_device_vulnerabilities(
    asset_id: int,
    db: Session = Depends(get_db)
):
    """
    Get detailed vulnerability information for a specific device
    
    Args:
        asset_id: Asset ID
        db: Database session
    
    Returns:
        Detailed vulnerability information
    """
    try:
        # Get asset using CRUD function
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Get CVEs for this asset using CRUD function
        cves = cve_crud.get_cves_by_asset_id(db, asset_id)
        
        vulnerabilities = []
        
        for cve in cves:
            # Get related CWEs using existing relationships
            cwe_relations = db.query(CVECWERelation).filter(
                CVECWERelation.cve_id == cve.id
            ).all()
            
            related_cwes = []
            for cwe_relation in cwe_relations:
                cwe = db.query(CWE).filter(CWE.id == cwe_relation.cwe_id).first()
                if cwe:
                    related_cwes.append({
                        "cwe_id": cwe.cwe_id,
                        "name": cwe.name,
                        "description": cwe.description
                    })
            
            vulnerabilities.append(VulnerabilityInfo(
                cve_id=cve.cve_id,
                description=cve.description,
                cvss=cve.cvss or 0.0,
                risk_level=cve.risk_level or 0.0,
                epss=cve.epss or 0.0,
                related_cwes=related_cwes
            ))
        
        device_info = DeviceInfo(
            id=asset.id,
            vendor=asset.vendor or "Unknown",
            model=asset.model or "Unknown",
            type=asset.type or "Unknown",
            department=asset.department or "Unknown",
            risk_level=asset.risk_level or 0.0
        )
        
        return DeviceVulnerabilityResponse(
            device=device_info,
            vulnerabilities=vulnerabilities,
            total_vulnerabilities=len(vulnerabilities)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving device vulnerabilities")


@router.get("/cpe-search")
async def search_cpe(device_name: str):
    """
    Search for CPE matches without running full scan
    
    Args:
        device_name: Device name to search for
    
    Returns:
        List of matching CPEs
    """
    try:
        cpe_matches = scanner.processor.find_matching_cpe(device_name)
        
        return {
            "device_name": device_name,
            "cpe_matches": cpe_matches[:10],  # Return top 10 matches
            "total_matches": len(cpe_matches)
        }
    except Exception as e:
        logger.error(f"CPE search failed: {e}")
        raise HTTPException(status_code=500, detail=f"CPE search failed: {str(e)}")


@router.get("/stats")
async def get_security_stats(db: Session = Depends(get_db)):
    """
    Get overall security statistics
    
    Returns:
        Security dashboard statistics
    """
    try:
        total_assets = db.query(Asset).count()
        vulnerable_assets = db.query(Asset).filter(Asset.risk_level > 0).count()
        total_cves = db.query(CVE).count()
        total_cwes = db.query(CWE).count()
        total_capecs = db.query(CAPEC).count()
        total_attacks = db.query(Attack).count()
        
        # Average risk level
        avg_risk_result = db.query(func.avg(Asset.risk_level)).scalar()
        avg_risk_level = float(avg_risk_result) if avg_risk_result else 0.0
        
        # High-risk assets (risk level > 50)
        high_risk_assets = db.query(Asset).filter(Asset.risk_level > 50).count()
        
        return {
            "total_assets": total_assets,
            "vulnerable_assets": vulnerable_assets,
            "total_cves": total_cves,
            "total_cwes": total_cwes,
            "total_capecs": total_capecs,
            "total_attacks": total_attacks,
            "average_risk_level": avg_risk_level,
            "high_risk_assets": high_risk_assets,
            "vulnerability_coverage": (vulnerable_assets / total_assets * 100) if total_assets > 0 else 0
        }
    except Exception as e:
        logger.error(f"Error getting security stats: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving security statistics")


@router.delete("/devices/{asset_id}")
async def delete_device(asset_id: int, db: Session = Depends(get_db)):
    """
    Delete a device and all its associated vulnerability data
    
    Args:
        asset_id: Asset ID to delete
        db: Database session
    
    Returns:
        Confirmation message
    """
    try:
        # Check if asset exists using CRUD function
        asset = asset_crud.get_asset(db, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Delete all relations first (this should be handled by cascade, but let's be explicit)
        db.query(AssetCVERelation).filter(AssetCVERelation.asset_id == asset_id).delete()
        
        # Use CRUD function to delete the asset
        deleted = asset_crud.delete_asset(db, asset_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return {"message": f"Device {asset.vendor} {asset.type} {asset.model} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        raise HTTPException(status_code=500, detail="Error deleting device")


@router.get("/health")
async def health_check():
    """
    Health check endpoint for the security scanner service
    """
    return {
        "status": "healthy",
        "service": "security-scanner",
        "scanner_initialized": scanner is not None
    }
