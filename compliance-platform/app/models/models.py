"""
Database Models - SQLAlchemy ORM
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, 
    ForeignKey, JSON, Text, Enum as SQLEnum
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.sql import func
import uuid
import enum


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


# Enums
class ControlStatus(str, enum.Enum):
    PASSING = "passing"
    FAILING = "failing"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Framework(str, enum.Enum):
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"


class AssetType(str, enum.Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK = "network"
    CLOUD = "cloud"
    APPLICATION = "application"
    DATABASE = "database"


# Models
class Organization(Base):
    """Multi-tenant organization."""
    __tablename__ = "organizations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    subscription_tier = Column(String(50), default="startup")  # startup, growth, enterprise
    active_frameworks = Column(ARRAY(String), default=[])
    settings = Column(JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    users = relationship("User", back_populates="organization")
    assets = relationship("Asset", back_populates="organization")
    controls = relationship("Control", back_populates="organization")
    risks = relationship("Risk", back_populates="organization")
    integrations = relationship("Integration", back_populates="organization")


class User(Base):
    """Platform users."""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(String(50), default="viewer")  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="users")


class Asset(Base):
    """IT Assets inventory."""
    __tablename__ = "assets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    asset_id = Column(String(100), nullable=False)  # e.g., SRV-PRD-WEB-001
    name = Column(String(255), nullable=False)
    asset_type = Column(SQLEnum(AssetType), nullable=False)
    owner = Column(String(255))
    location = Column(String(255))
    ip_address = Column(String(45))
    os_version = Column(String(100))
    criticality = Column(String(50), default="medium")
    status = Column(String(50), default="active")
    compliant = Column(Boolean, default=True)
    end_of_life = Column(DateTime(timezone=True))
    last_scanned = Column(DateTime(timezone=True))
    metadata = Column(JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="assets")
    vulnerabilities = relationship("Vulnerability", back_populates="asset")


class Control(Base):
    """Compliance controls."""
    __tablename__ = "controls"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    control_id = Column(String(50), nullable=False)  # e.g., CC6.1, PR.AC-1
    framework = Column(SQLEnum(Framework), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    family = Column(String(100))  # e.g., "Access Control", "Protect"
    status = Column(SQLEnum(ControlStatus), default=ControlStatus.NOT_ASSESSED)
    owner = Column(String(255))
    priority = Column(String(50), default="medium")
    implementation_notes = Column(Text)
    last_assessed = Column(DateTime(timezone=True))
    next_review = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="controls")
    evidence = relationship("Evidence", back_populates="control")
    
    # Cross-framework mappings stored as JSON
    mappings = Column(JSON, default={})  # {"iso_27001": "A.9.4.2", "soc2": "CC6.1"}


class Evidence(Base):
    """Evidence collected for controls."""
    __tablename__ = "evidence"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id = Column(UUID(as_uuid=True), ForeignKey("controls.id"), nullable=False)
    source = Column(String(100), nullable=False)  # aws, okta, github, manual
    evidence_type = Column(String(100))  # screenshot, config, log, report
    title = Column(String(255))
    description = Column(Text)
    data = Column(JSON)  # Raw evidence data
    file_url = Column(String(500))  # S3 URL for uploaded files
    collected_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    is_valid = Column(Boolean, default=True)
    
    # Relationships
    control = relationship("Control", back_populates="evidence")


class Risk(Base):
    """Risk register."""
    __tablename__ = "risks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    risk_id = Column(String(50), nullable=False)  # RISK-001
    title = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(100))  # technical, operational, compliance, financial
    
    # Inherent risk (before controls)
    likelihood = Column(Integer)  # 1-5
    impact = Column(Integer)  # 1-5
    inherent_score = Column(Float)  # likelihood * impact
    
    # Residual risk (after controls)
    residual_likelihood = Column(Integer)
    residual_impact = Column(Integer)
    residual_score = Column(Float)
    
    risk_level = Column(SQLEnum(RiskLevel))
    treatment = Column(String(50))  # accept, mitigate, transfer, avoid
    status = Column(String(50), default="open")  # open, in_treatment, closed, accepted
    owner = Column(String(255))
    controls = Column(ARRAY(String), default=[])  # List of control IDs
    due_date = Column(DateTime(timezone=True))
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="risks")


class Vulnerability(Base):
    """Vulnerabilities from scans."""
    __tablename__ = "vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    vuln_id = Column(String(50), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(RiskLevel))
    cvss_score = Column(Float)
    cve_ids = Column(ARRAY(String), default=[])
    port = Column(String(10))
    protocol = Column(String(10))
    solution = Column(Text)
    status = Column(String(50), default="open")  # open, in_progress, resolved, accepted
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    resolved_at = Column(DateTime(timezone=True))
    
    # Relationships
    asset = relationship("Asset", back_populates="vulnerabilities")


class Integration(Base):
    """Third-party integrations."""
    __tablename__ = "integrations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    provider = Column(String(100), nullable=False)  # aws, okta, github, etc.
    name = Column(String(255))
    status = Column(String(50), default="active")  # active, inactive, error
    credentials = Column(JSON)  # Encrypted credentials
    settings = Column(JSON, default={})
    last_sync = Column(DateTime(timezone=True))
    sync_frequency = Column(Integer, default=3600)  # seconds
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="integrations")


class AuditLog(Base):
    """Audit trail for compliance."""
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), nullable=False)
    user_id = Column(UUID(as_uuid=True))
    action = Column(String(100), nullable=False)  # create, update, delete, view
    resource_type = Column(String(100))  # control, risk, asset, etc.
    resource_id = Column(String(100))
    details = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
