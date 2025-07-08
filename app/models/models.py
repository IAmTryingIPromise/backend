from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, Float
from sqlalchemy.sql import func
from ..database import Base

# Placeholder model - replace with your actual models
class ApiResponse(Base):
    """
    Placeholder model for storing API responses
    Replace this with your actual models based on your requirements
    """
    __tablename__ = "api_responses"
    
    id = Column(Integer, primary_key=True, index=True)
    endpoint = Column(String, index=True)  # Which external API endpoint was called
    request_data = Column(JSON)  # Data sent to external API
    response_data = Column(JSON)  # Response received from external API
    status_code = Column(Integer)  # HTTP status code
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

# Example User model (commented out - uncomment and modify as needed)
"""
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
"""

class Asset(Base):

    __tablename__ = "asset"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, index=True)
    model = Column(String, index=True)
    vendor = Column(String, index=True)
    department = Column(String, index=True)
    risk_level = Column(Float, index=True)


class Asset2Cve(Base):

    __tablename__ = "asset2cve"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, index=True)
    cve_id = Column(Integer, index=True)


class Cve(Base):

    __tablename__ = "cve"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    description = Column(String)
    cvss = Column(Float)
    exploitability = Column(Float)
    impact = Column(Float)
    epss = Column(Float, default=0.0)
    risk_level = Column(Float, index=True)


class Asset2Cve(Base):

    __tablename__ = "cve2cwe"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, index=True)
    cwe_id = Column(Integer, index=True)


class Cwe(Base):

    __tablename__ = "cwe"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String, unique=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    common_consequenses = Column(String)
    potential_mitigations = Column(String)

class Asset2Cve(Base):

    __tablename__ = "cwe2capec"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(Integer, index=True)
    capec_id = Column(Integer, index=True)


class Capec(Base):

    __tablename__ = "capec"

    id = Column(Integer, primary_key=True, index=True)
    capec_id = Column(Integer, unique=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    likelihood_of_attack = Column(String)
    typical_severity = Column(String)
    related_weaknesses = Column(String)
    prerequisites = Column(String)
    mitigations = Column(String)
    consequences = Column(String)
    example_instances = Column(String)

class Asset2Cve(Base):

    __tablename__ = "capec2attack"

    id = Column(Integer, primary_key=True, index=True)
    capec_id = Column(Integer, index=True)
    attack_id = Column(Integer, index=True)


class Attack(Base):

    __tablename__ = "attack"

    id = Column(Integer, primary_key=True, index=True)
    attack_id = Column(Integer, unique=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    platforms = Column(String)
    tactics = Column(String)
    data_sources = Column(String)
    detection = Column(String)
    permissions_required = Column(String)
    url = Column(String)