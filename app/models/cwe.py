from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base

'''
class CWE(Base):
    __tablename__ = "cwes"
    
    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    weakness_type = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
'''

class CWE(Base):

    __tablename__ = "cwes"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    common_consequenses = Column(Text, nullable=True)
    potential_mitigations = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())