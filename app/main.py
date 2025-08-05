from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .database import create_tables
from app.routers import assets, cves
from app.database import engine, Base
from app.utils.logger import logger

# Create FastAPI app
app = FastAPI(
    title="Security Backend API",
    description="API for managing devices and their security information (CVEs, CWEs, CAPECs, ATT&CK)",
    version="1.0.0",
    debug=settings.debug
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(assets.router, prefix="/api/v1")
app.include_router(cves.router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "Security Backend API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )