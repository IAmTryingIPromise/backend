from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base

'''
class CAPEC(Base):
    __tablename__ = "capecs"
    
    id = Column(Integer, primary_key=True, index=True)
    capec_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    attack_pattern = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
'''

class CAPEC(Base):

    __tablename__ = "capecs"

    id = Column(Integer, primary_key=True, index=True)
    capec_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    likelihood_of_attack = Column(String, nullable=True)
    typical_severity = Column(String, nullable=True)
    related_weaknesses = Column(String, nullable=True)
    prerequisites = Column(Text, nullable=True)
    mitigations = Column(Text, nullable=True)
    consequences = Column(Text, nullable=True)
    example_instances = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    