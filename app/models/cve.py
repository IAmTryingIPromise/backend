from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from sqlalchemy.sql import func
from app.database import Base

'''
class CVE(Base):
    __tablename__ = "cves"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    published_date = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
'''

class CVE(Base):

    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    cvss = Column(Float, nullable=True)
    exploitability = Column(Float, nullable=True)
    impact = Column(Float, nullable=True)
    epss = Column(Float, nullable=True)
    risk_level = Column(Float, default=.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())