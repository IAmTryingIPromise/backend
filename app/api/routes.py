from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from ..database import get_db
from ..schemas.schemas import (
    GenericRequest, GenericResponse, ExternalApiRequest, 
    ApiResponseCreate, ApiResponseResponse
)
from ..crud.crud import api_response
from .external_api import external_api

router = APIRouter()

# Health check endpoint
@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "Backend is running"}

# Generic data endpoints for frontend communication
@router.post("/data/send", response_model=GenericResponse)
async def send_data_to_frontend(
    request: GenericRequest,
    db: Session = Depends(get_db)
):
    """
    Generic endpoint to send data to frontend
    This can be customized based on your specific needs
    """
    try:
        # Process the data here
        processed_data = {
            "received_data": request.data,
            "processed_at": "2024-01-01T00:00:00Z",  # Dummy timestamp
            "processed": True
        }
        
        return GenericResponse(
            success=True,
            data=processed_data,
            message="Data processed successfully"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing data: {str(e)}"
        )

@router.post("/data/receive", response_model=GenericResponse)
async def receive_data_from_frontend(
    request: GenericRequest,
    db: Session = Depends(get_db)
):
    """
    Generic endpoint to receive data from frontend
    """
    try:
        # Store received data in database (example)
        api_response_data = ApiResponseCreate(
            endpoint="frontend_data",
            request_data=request.data,
            response_data={"status": "received"},
            status_code=200
        )
        
        stored_response = api_response.create(db, api_response_data)
        
        return GenericResponse(
            success=True,
            data={"id": stored_response.id, "received": True},
            message="Data received and stored successfully"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error receiving data: {str(e)}"
        )

# External API endpoints
@router.post("/external-api/call", response_model=GenericResponse)
async def call_external_api(
    request: ExternalApiRequest,
    db: Session = Depends(get_db)
):
    """
    Call external API and store response
    """
    try:
        # Make external API call
        api_response_result = await external_api.make_request(request)
        
        # Store in database
        api_response_data = ApiResponseCreate(
            endpoint=request.endpoint,
            request_data=request.data,
            response_data=api_response_result.data,
            status_code=api_response_result.status_code
        )
        
        stored_response = api_response.create(db, api_response_data)
        
        return GenericResponse(
            success=api_response_result.success,
            data={
                "external_api_response": api_response_result.data,
                "stored_id": stored_response.id
            },
            message=api_response_result.message or "External API call completed",
            status_code=api_response_result.status_code
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error calling external API: {str(e)}"
        )

# Database endpoints
@router.get("/api-responses/", response_model=List[ApiResponseResponse])
async def get_api_responses(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get stored API responses"""
    responses = api_response.get_multi(db, skip=skip, limit=limit)
    return responses

@router.get("/api-responses/{response_id}", response_model=ApiResponseResponse)
async def get_api_response(
    response_id: int,
    db: Session = Depends(get_db)
):
    """Get specific API response by ID"""
    response = api_response.get(db, response_id)
    if not response:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API response not found"
        )
    return response

# Example endpoint with dummy data
@router.get("/dummy-data")
async def get_dummy_data():
    """Returns dummy data for testing"""
    return {
        "users": [
            {"id": 1, "name": "John Doe", "email": "john@example.com"},
            {"id": 2, "name": "Jane Smith", "email": "jane@example.com"}
        ],
        "products": [
            {"id": 1, "name": "Product A", "price": 99.99},
            {"id": 2, "name": "Product B", "price": 149.99}
        ],
        "timestamp": "2024-01-01T00:00:00Z"
    }