from sqlalchemy import Column, Integer, ForeignKey, DateTime
from sqlalchemy.sql import func
from app.database import Base

class AssetCVERelation(Base):
    __tablename__ = "asset_cve_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    cve_id = Column(Integer, ForeignKey("cves.id"), nullable=False)

class CVECWERelation(Base):
    __tablename__ = "cve_cwe_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id"), nullable=False)
    cwe_id = Column(Integer, ForeignKey("cwes.id"), nullable=False)

class CWECAPECRelation(Base):
    __tablename__ = "cwe_capec_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(Integer, ForeignKey("cwes.id"), nullable=False)
    capec_id = Column(Integer, ForeignKey("capecs.id"), nullable=False)

class CAPECAttackRelation(Base):
    __tablename__ = "capec_attack_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    capec_id = Column(Integer, ForeignKey("capecs.id"), nullable=False)
    attack_id = Column(Integer, ForeignKey("attacks.id"), nullable=False)