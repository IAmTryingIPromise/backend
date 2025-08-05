# Project Structure:
# my_app/
# ├── app/
# │   ├── __init__.py
# │   ├── main.py
# │   ├── database.py
# │   ├── config.py
# │   ├── models/
# │   │   ├── __init__.py
# │   │   ├── user.py
# │   │   └── item.py
# │   ├── schemas/
# │   │   ├── __init__.py
# │   │   ├── user.py
# │   │   └── item.py
# │   ├── crud/
# │   │   ├── __init__.py
# │   │   ├── user.py
# │   │   └── item.py
# │   └── routers/
# │       ├── __init__.py
# │       ├── users.py
# │       └── items.py
# ├── alembic/
# │   └── versions/
# ├── alembic.ini
# ├── requirements.txt
# ├── .env
# ├── .env.example
# └── README.md

# =============================================================================
# requirements.txt
# =============================================================================
fastapi==0.104.1
uvicorn[standard]==0.24.0
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
alembic==1.12.1
pydantic==2.5.0
python-dotenv==1.0.0
python-multipart==0.0.6

# =============================================================================
# .env.example
# =============================================================================
DATABASE_URL=postgresql://username:password@localhost:5432/dbname
SECRET_KEY=your-secret-key-here
DEBUG=True
HOST=0.0.0.0
PORT=8000

# =============================================================================
# app/config.py
# =============================================================================
from pydantic import BaseSettings
from functools import lru_cache
import os
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    database_url: str = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/mydb")
    secret_key: str = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
    debug: bool = os.getenv("DEBUG", "False").lower() == "true"
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()

# =============================================================================
# app/database.py
# =============================================================================
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import get_settings

settings = get_settings()

# Create SQLAlchemy engine
engine = create_engine(
    settings.database_url,
    echo=settings.debug,  # Log SQL queries when debug is True
    pool_pre_ping=True,   # Verify connections before use
)

# Create sessionmaker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create declarative base
Base = declarative_base()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =============================================================================
# app/models/__init__.py
# =============================================================================
from .user import User
from .item import Item

__all__ = ["User", "Item"]

# =============================================================================
# app/models/user.py
# =============================================================================
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationship with items
    items = relationship("Item", back_populates="owner")
    
    # Add indexes for better query performance
    __table_args__ = (
        Index('idx_user_email_active', 'email', 'is_active'),
        Index('idx_user_username_active', 'username', 'is_active'),
    )

# =============================================================================
# app/models/item.py
# =============================================================================
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base

class Item(Base):
    __tablename__ = "items"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=True)
    price = Column(Integer, nullable=False)  # Store price in cents
    is_available = Column(Boolean, default=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationship with user
    owner = relationship("User", back_populates="items")
    
    # Add indexes for better query performance
    __table_args__ = (
        Index('idx_item_owner_available', 'owner_id', 'is_available'),
        Index('idx_item_title_available', 'title', 'is_available'),
    )

# =============================================================================
# app/schemas/__init__.py
# =============================================================================
from .user import UserCreate, UserUpdate, UserInDB, UserResponse
from .item import ItemCreate, ItemUpdate, ItemInDB, ItemResponse

__all__ = [
    "UserCreate", "UserUpdate", "UserInDB", "UserResponse",
    "ItemCreate", "ItemUpdate", "ItemInDB", "ItemResponse"
]

# =============================================================================
# app/schemas/user.py
# =============================================================================
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr
    username: str
    is_active: bool = True
    is_superuser: bool = False

class UserCreate(UserBase):
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        return v

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    
    @validator('password')
    def validate_password(cls, v):
        if v is not None and len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class UserInDB(UserBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class UserResponse(UserInDB):
    # Don't include sensitive fields like hashed_password
    pass

# Import here to avoid circular imports
from .item import ItemResponse

class UserWithItems(UserResponse):
    items: List[ItemResponse] = []

# =============================================================================
# app/schemas/item.py
# =============================================================================
from pydantic import BaseModel, validator
from typing import Optional
from datetime import datetime

class ItemBase(BaseModel):
    title: str
    description: Optional[str] = None
    price: int  # Price in cents
    is_available: bool = True
    
    @validator('price')
    def validate_price(cls, v):
        if v <= 0:
            raise ValueError('Price must be greater than 0')
        return v
    
    @validator('title')
    def validate_title(cls, v):
        if len(v.strip()) < 3:
            raise ValueError('Title must be at least 3 characters long')
        return v.strip()

class ItemCreate(ItemBase):
    pass

class ItemUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[int] = None
    is_available: Optional[bool] = None
    
    @validator('price')
    def validate_price(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Price must be greater than 0')
        return v

class ItemInDB(ItemBase):
    id: int
    owner_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class ItemResponse(ItemInDB):
    pass

# Import here to avoid circular imports
from .user import UserResponse

class ItemWithOwner(ItemResponse):
    owner: UserResponse

# =============================================================================
# app/crud/__init__.py
# =============================================================================
from .user import user_crud
from .item import item_crud

__all__ = ["user_crud", "item_crud"]

# =============================================================================
# app/crud/user.py
# =============================================================================
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional, List
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate
import hashlib
import secrets

class UserCrud:
    def get_user(self, db: Session, user_id: int) -> Optional[User]:
        return db.query(User).filter(User.id == user_id).first()
    
    def get_user_by_email(self, db: Session, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email).first()
    
    def get_user_by_username(self, db: Session, username: str) -> Optional[User]:
        return db.query(User).filter(User.username == username).first()
    
    def get_users(self, db: Session, skip: int = 0, limit: int = 100) -> List[User]:
        return db.query(User).offset(skip).limit(limit).all()
    
    def create_user(self, db: Session, user: UserCreate) -> User:
        hashed_password = self._hash_password(user.password)
        db_user = User(
            email=user.email,
            username=user.username,
            hashed_password=hashed_password,
            is_active=user.is_active,
            is_superuser=user.is_superuser
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    
    def update_user(self, db: Session, user_id: int, user_update: UserUpdate) -> Optional[User]:
        db_user = self.get_user(db, user_id)
        if not db_user:
            return None
        
        update_data = user_update.dict(exclude_unset=True)
        
        # Handle password hashing if password is being updated
        if 'password' in update_data:
            update_data['hashed_password'] = self._hash_password(update_data.pop('password'))
        
        for field, value in update_data.items():
            setattr(db_user, field, value)
        
        db.commit()
        db.refresh(db_user)
        return db_user
    
    def delete_user(self, db: Session, user_id: int) -> bool:
        db_user = self.get_user(db, user_id)
        if not db_user:
            return False
        
        db.delete(db_user)
        db.commit()
        return True
    
    def authenticate_user(self, db: Session, email_or_username: str, password: str) -> Optional[User]:
        # Try to find user by email or username
        user = db.query(User).filter(
            or_(User.email == email_or_username, User.username == email_or_username)
        ).first()
        
        if not user:
            return None
        
        if not self._verify_password(password, user.hashed_password):
            return None
        
        return user
    
    def _hash_password(self, password: str) -> str:
        """
        Hash a password using SHA-256 with salt.
        In production, use bcrypt or similar library.
        """
        salt = secrets.token_hex(32)
        pwdhash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}${pwdhash}"
    
    def _verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        """
        try:
            salt, pwdhash = hashed_password.split('$')
            return pwdhash == hashlib.sha256((password + salt).encode()).hexdigest()
        except ValueError:
            return False

# Create singleton instance
user_crud = UserCrud()

# =============================================================================
# app/crud/item.py
# =============================================================================
from sqlalchemy.orm import Session
from typing import Optional, List
from app.models.item import Item
from app.schemas.item import ItemCreate, ItemUpdate

class ItemCrud:
    def get_item(self, db: Session, item_id: int) -> Optional[Item]:
        return db.query(Item).filter(Item.id == item_id).first()
    
    def get_items(self, db: Session, skip: int = 0, limit: int = 100) -> List[Item]:
        return db.query(Item).offset(skip).limit(limit).all()
    
    def get_available_items(self, db: Session, skip: int = 0, limit: int = 100) -> List[Item]:
        return db.query(Item).filter(Item.is_available == True).offset(skip).limit(limit).all()
    
    def get_items_by_user(self, db: Session, user_id: int, skip: int = 0, limit: int = 100) -> List[Item]:
        return db.query(Item).filter(Item.owner_id == user_id).offset(skip).limit(limit).all()
    
    def create_item(self, db: Session, item: ItemCreate, owner_id: int) -> Item:
        db_item = Item(**item.dict(), owner_id=owner_id)
        db.add(db_item)
        db.commit()
        db.refresh(db_item)
        return db_item
    
    def update_item(self, db: Session, item_id: int, item_update: ItemUpdate) -> Optional[Item]:
        db_item = self.get_item(db, item_id)
        if not db_item:
            return None
        
        update_data = item_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_item, field, value)
        
        db.commit()
        db.refresh(db_item)
        return db_item
    
    def delete_item(self, db: Session, item_id: int) -> bool:
        db_item = self.get_item(db, item_id)
        if not db_item:
            return False
        
        db.delete(db_item)
        db.commit()
        return True
    
    def search_items(self, db: Session, query: str, skip: int = 0, limit: int = 100) -> List[Item]:
        return db.query(Item).filter(
            Item.title.ilike(f"%{query}%"),
            Item.is_available == True
        ).offset(skip).limit(limit).all()

# Create singleton instance
item_crud = ItemCrud()

# =============================================================================
# app/routers/__init__.py
# =============================================================================
from .users import router as users_router
from .items import router as items_router

__all__ = ["users_router", "items_router"]

# =============================================================================
# app/routers/users.py
# =============================================================================
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.crud.user import user_crud
from app.schemas.user import UserCreate, UserUpdate, UserResponse, UserWithItems

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """Create a new user."""
    # Check if user already exists
    if user_crud.get_user_by_email(db, user.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    if user_crud.get_user_by_username(db, user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    return user_crud.create_user(db, user)

@router.get("/", response_model=List[UserResponse])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all users with pagination."""
    users = user_crud.get_users(db, skip=skip, limit=limit)
    return users

@router.get("/{user_id}", response_model=UserResponse)
def read_user(user_id: int, db: Session = Depends(get_db)):
    """Get a specific user by ID."""
    db_user = user_crud.get_user(db, user_id)
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return db_user

@router.get("/{user_id}/items", response_model=UserWithItems)
def read_user_with_items(user_id: int, db: Session = Depends(get_db)):
    """Get a user with their items."""
    db_user = user_crud.get_user(db, user_id)
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return db_user

@router.put("/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    """Update a user."""
    db_user = user_crud.update_user(db, user_id, user_update)
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return db_user

@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """Delete a user."""
    if not user_crud.delete_user(db, user_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return {"message": "User deleted successfully"}

@router.post("/authenticate", response_model=UserResponse)
def authenticate_user(email_or_username: str, password: str, db: Session = Depends(get_db)):
    """Authenticate a user."""
    user = user_crud.authenticate_user(db, email_or_username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    return user

# =============================================================================
# app/routers/items.py
# =============================================================================
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.crud.item import item_crud
from app.crud.user import user_crud
from app.schemas.item import ItemCreate, ItemUpdate, ItemResponse, ItemWithOwner

router = APIRouter(
    prefix="/items",
    tags=["items"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=ItemResponse, status_code=status.HTTP_201_CREATED)
def create_item(item: ItemCreate, owner_id: int, db: Session = Depends(get_db)):
    """Create a new item."""
    # Verify that the owner exists
    if not user_crud.get_user(db, owner_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Owner not found"
        )
    
    return item_crud.create_item(db, item, owner_id)

@router.get("/", response_model=List[ItemResponse])
def read_items(
    skip: int = 0,
    limit: int = 100,
    available_only: bool = Query(False, description="Filter only available items"),
    db: Session = Depends(get_db)
):
    """Get all items with pagination and optional filtering."""
    if available_only:
        items = item_crud.get_available_items(db, skip=skip, limit=limit)
    else:
        items = item_crud.get_items(db, skip=skip, limit=limit)
    return items

@router.get("/search", response_model=List[ItemResponse])
def search_items(
    q: str = Query(..., description="Search query"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Search items by title."""
    items = item_crud.search_items(db, q, skip=skip, limit=limit)
    return items

@router.get("/{item_id}", response_model=ItemResponse)
def read_item(item_id: int, db: Session = Depends(get_db)):
    """Get a specific item by ID."""
    db_item = item_crud.get_item(db, item_id)
    if db_item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found"
        )
    return db_item

@router.get("/{item_id}/with-owner", response_model=ItemWithOwner)
def read_item_with_owner(item_id: int, db: Session = Depends(get_db)):
    """Get an item with its owner information."""
    db_item = item_crud.get_item(db, item_id)
    if db_item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found"
        )
    return db_item

@router.put("/{item_id}", response_model=ItemResponse)
def update_item(item_id: int, item_update: ItemUpdate, db: Session = Depends(get_db)):
    """Update an item."""
    db_item = item_crud.update_item(db, item_id, item_update)
    if db_item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found"
        )
    return db_item

@router.delete("/{item_id}")
def delete_item(item_id: int, db: Session = Depends(get_db)):
    """Delete an item."""
    if not item_crud.delete_item(db, item_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found"
        )
    return {"message": "Item deleted successfully"}

@router.get("/user/{user_id}", response_model=List[ItemResponse])
def read_user_items(
    user_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get all items belonging to a specific user."""
    # Verify that the user exists
    if not user_crud.get_user(db, user_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    items = item_crud.get_items_by_user(db, user_id, skip=skip, limit=limit)
    return items

# =============================================================================
# app/main.py
# =============================================================================
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from contextlib import asynccontextmanager
from sqlalchemy import text

from app.config import get_settings
from app.database import engine, Base
from app.routers import users_router, items_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

settings = get_settings()

# Lifespan event handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting up...")
    
    # Test database connection
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        logger.info("Database connection successful")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise
    
    # TODO: Add any other startup tasks here
    # - Initialize cache
    # - Setup background tasks
    # - Load configuration
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    # TODO: Add cleanup tasks here
    # - Close database connections
    # - Clean up resources

# Create FastAPI app
app = FastAPI(
    title="My FastAPI Backend",
    description="A complete FastAPI backend with SQLAlchemy, PostgreSQL, and Alembic",
    version="1.0.0",
    debug=settings.debug,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Configure this properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# Include routers
app.include_router(users_router)
app.include_router(items_router)

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to My FastAPI Backend",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}

# =============================================================================
# alembic.ini
# =============================================================================
[alembic]
script_location = alembic
prepend_sys_path = .
version_path_separator = os

sqlalchemy.url = postgresql://user:password@localhost:5432/mydb

[post_write_hooks]

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S

# =============================================================================
# alembic/env.py
# =============================================================================
from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys

# Add parent directory to path so we can import our app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base
from app.config import get_settings

# Import all models so Alembic can detect them
from app.models import User, Item

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set the database URL from our settings
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)

# add your model's MetaData object here for 'autogenerate' support
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

# =============================================================================
# README.md
# =============================================================================

# My FastAPI Backend

A complete FastAPI backend with SQLAlchemy, PostgreSQL, and Alembic for database migrations.

## Features

- **FastAPI** - Modern, fast web framework for building APIs
- **SQLAlchemy** - SQL toolkit and Object-Relational Mapping (ORM)
- **PostgreSQL** - Powerful, open source object-relational database
- **Alembic** - Database migration tool for SQLAlchemy
- **Pydantic** - Data validation and settings management using Python type hints
- **Uvicorn** - ASGI server for serving the application

## Project Structure

```
my_app/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app initialization
│   ├── database.py          # Database configuration
│   ├── config.py            # Application settings
│   ├── models/              # SQLAlchemy models
│   │   ├── __init__.py
│   │   ├── user.py
│   │   └── item.py
│   ├── schemas/             # Pydantic schemas
│   │   ├── __init__.py
│   │   ├── user.py
│   │   └── item.py
│   ├── crud/                # Database operations
│   │   ├── __init__.py
│   │   ├── user.py
│   │   └── item.py
│   └── routers/             # API routes
│       ├── __init__.py
│       ├── users.py
│       └── items.py
├── alembic/                 # Database migrations
│   ├── versions/
│   └── env.py
├── alembic.ini
├── requirements.txt
├── .env
├── .env.example
└── README.md
```

## Setup Instructions

### 1. Create Project Structure

```bash
# Create the project directory
mkdir my_app
cd my_app

# Create the application structure
mkdir -p app/{models,schemas,crud,routers}
mkdir -p alembic/versions

# Create __init__.py files
touch app/__init__.py
touch app/models/__init__.py
touch app/schemas/__init__.py
touch app/crud/__init__.py
touch app/routers/__init__.py
```

### 2. Set Up Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt
```

### 4. Database Setup

#### Option A: Using Docker (Recommended)

```bash
# Run PostgreSQL in Docker
docker run --name postgres-db \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=mydb \
  -p 5432:5432 \
  -d postgres:13
```

#### Option B: Install PostgreSQL Locally

1. Install PostgreSQL from https://www.postgresql.org/download/
2. Create a database:
```sql
CREATE DATABASE mydb;
CREATE USER myuser WITH PASSWORD 'mypassword';
GRANT ALL PRIVILEGES ON DATABASE mydb TO myuser;
```

### 5. Environment Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env file with your database credentials
# DATABASE_URL=postgresql://myuser:mypassword@localhost:5432/mydb
```

### 6. Initialize Alembic

```bash
# Initialize Alembic (already done in this template)
alembic init alembic

# Generate initial migration
alembic revision --autogenerate -m "Initial migration"

# Apply migrations
alembic upgrade head
```

### 7. Run the Application

```bash
# Start the development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at:
- **API**: http://localhost:8000
- **Interactive API docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## API Endpoints

### Users
- `POST /users/` - Create a new user
- `GET /users/` - Get all users (paginated)
- `GET /users/{user_id}` - Get a specific user
- `GET /users/{user_id}/items` - Get a user with their items
- `PUT /users/{user_id}` - Update a user
- `DELETE /users/{user_id}` - Delete a user
- `POST /users/authenticate` - Authenticate a user

### Items
- `POST /items/` - Create a new item
- `GET /items/` - Get all items (paginated)
- `GET /items/search` - Search items by title
- `GET /items/{item_id}` - Get a specific item
- `GET /items/{item_id}/with-owner` - Get an item with owner info
- `PUT /items/{item_id}` - Update an item
- `DELETE /items/{item_id}` - Delete an item
- `GET /items/user/{user_id}` - Get all items by a user

### Health Check
- `GET /health` - Check API and database health

## Database Models

### User Model
- `id` - Primary key
- `email` - Unique email address
- `username` - Unique username
- `hashed_password` - Hashed password
- `is_active` - Boolean flag for active users
- `is_superuser` - Boolean flag for admin users
- `created_at` - Timestamp of creation
- `updated_at` - Timestamp of last update

### Item Model
- `id` - Primary key
- `title` - Item title
- `description` - Item description (optional)
- `price` - Price in cents
- `is_available` - Boolean flag for availability
- `owner_id` - Foreign key to User
- `created_at` - Timestamp of creation
- `updated_at` - Timestamp of last update

## Development Commands

```bash
# Create a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head

# Rollback migrations
alembic downgrade -1

# Check migration status
alembic current

# View migration history
alembic history
```

## Production Considerations

### Security
- [ ] Change the SECRET_KEY in production
- [ ] Use environment variables for sensitive data
- [ ] Implement proper authentication/authorization (JWT tokens)
- [ ] Use HTTPS in production
- [ ] Configure CORS properly
- [ ] Implement rate limiting

### Performance
- [ ] Add database indexes for frequently queried fields
- [ ] Implement caching (Redis)
- [ ] Add connection pooling
- [ ] Monitor database queries
- [ ] Implement background tasks for heavy operations

### Monitoring
- [ ] Add structured logging
- [ ] Implement health checks
- [ ] Add metrics collection
- [ ] Set up error tracking (Sentry)
- [ ] Monitor database performance

### Deployment
- [ ] Use Docker for containerization
- [ ] Set up CI/CD pipeline
- [ ] Use production ASGI server (Gunicorn with Uvicorn workers)
- [ ] Configure load balancing
- [ ] Set up database backups

## Testing

### Running Tests
```bash
# TODO: Add test dependencies to requirements.txt
# pytest==7.4.3
# httpx==0.25.2
# pytest-asyncio==0.21.1

# Run tests
pytest

# Run tests with coverage
pytest --cov=app
```

### Test Structure
```
tests/
├── __init__.py
├── conftest.py           # Test configuration
├── test_users.py         # User endpoint tests
├── test_items.py         # Item endpoint tests
└── test_database.py      # Database tests
```

## Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Check if PostgreSQL is running
   - Verify database credentials in .env
   - Ensure database exists

2. **Migration Errors**
   - Check if models are properly imported in alembic/env.py
   - Verify database connection
   - Check for model conflicts

3. **Import Errors**
   - Ensure all __init__.py files are present
   - Check Python path configuration
   - Verify virtual environment is activated

### Useful Commands

```bash
# Check database connection
python -c "from app.database import engine; print(engine.execute('SELECT 1').scalar())"

# Reset database (development only)
alembic downgrade base
alembic upgrade head

# Check installed packages
pip list

# Update dependencies
pip freeze > requirements.txt
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Run tests and ensure they pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

# =============================================================================
# Docker Setup (Optional)
# =============================================================================

# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# =============================================================================
# docker-compose.yml
# =============================================================================

version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    depends_on:
      - db
    environment:
      - DATABASE_URL=postgresql://myuser:mypassword@db:5432/mydb
      - SECRET_KEY=your-secret-key-here
      - DEBUG=True
    volumes:
      - .:/app
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

  db:
    image: postgres:13
    environment:
      - POSTGRES_USER=myuser
      - POSTGRES_PASSWORD=mypassword
      - POSTGRES_DB=mydb
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:

# =============================================================================
# .gitignore
# =============================================================================

# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/
cover/

# Translations
*.mo
*.pot

# Django stuff:
*.log
local_settings.py
db.sqlite3
db.sqlite3-journal

# Flask stuff:
instance/
.webassets-cache

# Scrapy stuff:
.scrapy

# Sphinx documentation
docs/_build/

# PyBuilder
.pybuilder/
target/

# Jupyter Notebook
.ipynb_checkpoints

# IPython
profile_default/
ipython_config.py

# pyenv
.python-version

# pipenv
Pipfile.lock

# poetry
poetry.lock

# pdm
.pdm.toml

# PEP 582
__pypackages__/

# Celery stuff
celerybeat-schedule
celerybeat.pid

# SageMath parsed files
*.sage.py

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Spyder project settings
.spyderproject
.spyproject

# Rope project settings
.ropeproject

# mkdocs documentation
/site

# mypy
.mypy_cache/
.dmypy.json
dmypy.json

# Pyre type checker
.pyre/

# pytype static type analyzer
.pytype/

# Cython debug symbols
cython_debug/

# PyCharm
.idea/

# VS Code
.vscode/

# Alembic
alembic/versions/*.py
!alembic/versions/

# Database
*.db
*.sqlite

# Logs
*.log

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# =============================================================================
# Setup Commands and Instructions
# =============================================================================

# COMPLETE SETUP INSTRUCTIONS:

# 1. Create project structure:
mkdir my_app
cd my_app
mkdir -p app/{models,schemas,crud,routers}
mkdir -p alembic/versions
touch app/__init__.py app/models/__init__.py app/schemas/__init__.py app/crud/__init__.py app/routers/__init__.py

# 2. Copy all the files from the artifact above into their respective locations

# 3. Set up virtual environment:
python -m venv venv
# On Windows: venv\Scripts\activate
# On macOS/Linux: source venv/bin/activate

# 4. Install dependencies:
pip install -r requirements.txt

# 5. Set up PostgreSQL (choose one):
# Option A - Docker:
docker run --name postgres-db -e POSTGRES_USER=myuser -e POSTGRES_PASSWORD=mypassword -e POSTGRES_DB=mydb -p 5432:5432 -d postgres:13

# Option B - Install PostgreSQL locally and create database

# 6. Configure environment:
cp .env.example .env
# Edit .env with your database credentials

# 7. Initialize database:
alembic revision --autogenerate -m "Initial migration"
alembic upgrade head

# 8. Run the application:
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 9. Test the API:
# Visit http://localhost:8000/docs for interactive API documentation
# Visit http://localhost:8000/health to check if everything is working

# =============================================================================
# PLACEHOLDER IMPLEMENTATIONS TO COMPLETE:
# =============================================================================

# 1. Authentication & Authorization:
# - Implement JWT token generation and validation
# - Add authentication middleware
# - Add role-based access control
# - Add password reset functionality

# 2. Enhanced Security:
# - Replace simple password hashing with bcrypt
# - Add rate limiting
# - Input sanitization
# - CSRF protection

# 3. Caching:
# - Add Redis for caching
# - Implement cache decorators
# - Cache frequently accessed data

# 4. File Upload:
# - Add file upload endpoints
# - Image processing
# - File storage (local/S3)

# 5. Background Tasks:
# - Add Celery for background tasks
# - Email sending
# - Data processing tasks

# 6. Testing:
# - Add comprehensive test suite
# - Unit tests for CRUD operations
# - Integration tests for API endpoints
# - Test fixtures and mocking

# 7. Monitoring & Logging:
# - Add structured logging
# - Health check endpoints
# - Metrics collection
# - Error tracking

# 8. Documentation:
# - API documentation
# - Developer guide
# - Deployment guide

# Your backend is now ready to use! 🚀