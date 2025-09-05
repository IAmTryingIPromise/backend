from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
import os
import sys
import time
from pathlib import Path
from sqlalchemy import text

# Add the project root to Python path
PROJECT_ROOT = Path(__file__).parent
#DATA_PATH_PREFIX = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import application components
from app.database import engine, get_db, Base, SessionLocal
from app.utils.logger import logger
from app.routers import security
from app.services.security_vulnerability_scanner_service import VulnerabilityScanner

# Import models to ensure they're registered with SQLAlchemy
from app.models import asset, cve, cwe, capec, attack, relations

# Import settings
from app.config import settings

# Environment configuration
ENVIRONMENT = settings.environment
DEBUG_MODE = settings.debug
API_PREFIX = settings.api_prefix
HOST = settings.api_host
PORT = settings.api_port

# CORS configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
ALLOWED_HEADERS = ["*"]

# Security configuration
SECRET_KEY = settings.secret_key
NVD_API_KEY = settings.nvd_api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for startup and shutdown events
    """
    logger.info("Starting Security Vulnerability Scanner API...")
    
    try:
        # Create database tables
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        # Initialize vulnerability scanner
        logger.info("Initializing vulnerability scanner...")
        scanner = VulnerabilityScanner(NVD_API_KEY, str(PROJECT_ROOT))
        app.state.scanner = scanner
        logger.info("Vulnerability scanner initialized successfully")
        
        # Verify data files exist
        data_dir = PROJECT_ROOT / "data"
        if not data_dir.exists():
            logger.warning(f"Data directory not found: {data_dir}")
        else:
            logger.info(f"Data directory found: {data_dir}")
            # Log available data files
            for file_type in ["*.json", "*.csv"]:
                files = list(data_dir.glob(file_type))
                if files:
                    logger.info(f"Found {file_type} files: {[f.name for f in files]}")
        
        logger.info("Application startup completed successfully")
        
    except Exception as e:
        logger.error(f"Startup failed: {str(e)}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Security Vulnerability Scanner API...")
    logger.info("Application shutdown completed")


# Create FastAPI application
app = FastAPI(
    title="Security Vulnerability Scanner API",
    description="A comprehensive API for scanning devices and analyzing security vulnerabilities using CVE, CWE, CAPEC, and MITRE ATT&CK data",
    version="1.0.0",
    docs_url="/docs" if DEBUG_MODE else None,
    redoc_url="/redoc" if DEBUG_MODE else None,
    openapi_url="/openapi.json" if DEBUG_MODE else None,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=ALLOWED_METHODS,
    allow_headers=ALLOWED_HEADERS,
)

# Add trusted host middleware for production
if ENVIRONMENT == "production":
    trusted_hosts = os.getenv("TRUSTED_HOSTS", "localhost").split(",")
    app.add_middleware(
        TrustedHostMiddleware, 
        allowed_hosts=trusted_hosts
    )


# Global exception handler
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTP {exc.status_code} error on {request.method} {request.url}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url}: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "status_code": 500}
    )


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Log request
    logger.info(f"Incoming request: {request.method} {request.url}")
    
    # Process request
    response = await call_next(request)
    
    # Log response
    process_time = time.time() - start_time
    logger.info(f"Request completed: {request.method} {request.url} - {response.status_code} in {process_time:.4f}s")
    
    return response


# Health check endpoint
@app.get("/health")
async def health_check():
    """Application health check"""
    try:
        # Test database connection
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_status = "connected"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "disconnected"
    
    return {
        "status": "healthy",
        "service": "security-vulnerability-scanner",
        "version": "1.0.0",
        "environment": ENVIRONMENT,
        "components": {
            "database": db_status,
            "scanner": "initialized" if hasattr(app.state, 'scanner') else "not_initialized",
            "nvd_api": "configured" if NVD_API_KEY else "not_configured"
        }
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Security Vulnerability Scanner API",
        "version": "1.0.0",
        "docs": "/docs" if DEBUG_MODE else "Documentation disabled in production",
        "health": "/health"
    }


# Include routers
app.include_router(
    security.router,
    prefix=API_PREFIX,
    tags=["Security Scanner"]
)

# Additional routers can be added here
# app.include_router(auth.router, prefix=API_PREFIX + "/auth", tags=["Authentication"])
# app.include_router(admin.router, prefix=API_PREFIX + "/admin", tags=["Administration"])

'''
if __name__ == "__main__":
    import time
    
    logger.info(f"Starting server in {ENVIRONMENT} mode...")
    logger.info(f"Debug mode: {DEBUG_MODE}")
    logger.info(f"API documentation: {'Enabled' if DEBUG_MODE else 'Disabled'}")
    logger.info(f"CORS origins: {ALLOWED_ORIGINS}")
    
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=DEBUG_MODE,
        log_level="info" if DEBUG_MODE else "warning",
        access_log=DEBUG_MODE,
    )'''