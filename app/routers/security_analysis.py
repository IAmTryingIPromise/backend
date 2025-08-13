# app/routers/security_analysis.py
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any
import logging

from app.database import get_db
from app.services.service_unused import SecurityAnalysisService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security", tags=["Security Analysis"])

class DeviceAnalysisRequest(BaseModel):
    device_name: str

class DeviceAnalysisResponse(BaseModel):
    success: bool
    message: str
    device_name: str
    device_id: int = None
    cpe: str = None
    vulnerable_cves: int = None
    unique_cwes: int = None
    capec_entries: int = None
    attack_techniques: int = None
    total_cves: int = None

@router.post("/analyze-device", response_model=DeviceAnalysisResponse)
async def analyze_device_security(
    request: DeviceAnalysisRequest,
    db: Session = Depends(get_db)
):
    """
    Analyze device security:
    1. Find matching CPE for device name
    2. Get CVEs from NVD API
    3. Filter vulnerable CVEs
    4. Get CWE, CAPEC, and ATT&CK data
    5. Store results in database
    """
    try:
        logger.info(f"Starting security analysis for device: {request.device_name}")
        
        # Initialize service
        analysis_service = SecurityAnalysisService(db)
        
        # Run analysis
        result = await analysis_service.analyze_device(request.device_name)
        
        logger.info(f"Analysis completed for {request.device_name}: {result['message']}")
        
        return DeviceAnalysisResponse(**result)
        
    except Exception as e:
        logger.error(f"Analysis failed for {request.device_name}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Security analysis failed: {str(e)}"
        )

@router.post("/analyze-device-background", response_model=Dict[str, str])
async def analyze_device_security_background(
    request: DeviceAnalysisRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Run security analysis in background (for long-running analyses)
    """
    try:
        logger.info(f"Starting background security analysis for device: {request.device_name}")
        
        # Add analysis to background tasks
        background_tasks.add_task(
            run_background_analysis, 
            request.device_name, 
            db
        )
        
        return {
            "message": f"Security analysis started for {request.device_name}",
            "status": "processing"
        }
        
    except Exception as e:
        logger.error(f"Failed to start background analysis for {request.device_name}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to start analysis: {str(e)}"
        )

async def run_background_analysis(device_name: str, db: Session):
    """Background task for running analysis"""
    try:
        analysis_service = SecurityAnalysisService(db)
        result = await analysis_service.analyze_device(device_name)
        logger.info(f"Background analysis completed for {device_name}: {result['message']}")
    except Exception as e:
        logger.error(f"Background analysis failed for {device_name}: {str(e)}")

# Optional: Add endpoint to get analysis status/results
@router.get("/device/{device_id}/analysis")
async def get_device_analysis(
    device_id: int,
    db: Session = Depends(get_db)
):
    """
    Get stored analysis results for a device
    """
    try:
        # Use your existing CRUD operations to fetch device data
        from app.crud import device_crud
        
        device = device_crud.get_device_by_id(db, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Fetch related data using your existing relationships
        # This would depend on your actual model relationships
        
        return {
            "device_id": device.id,
            "device_name": device.name,
            "cpe": device.cpe,
            "created_at": device.created_at,
            "updated_at": device.updated_at,
            # Add more fields based on your relationships
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get analysis for device {device_id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to get analysis results: {str(e)}"
        )