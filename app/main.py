from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .database import create_tables
from .api.routes import router

# Create FastAPI app
app = FastAPI(
    title="FastAPI Backend",
    description="Complete backend architecture with PostgreSQL and external API integration",
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
app.include_router(router, prefix="/api/v1", tags=["api"])

@app.on_event("startup")
async def startup_event():
    """Create database tables on startup"""
    create_tables()
    print("Database tables created successfully")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "FastAPI Backend is running",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )