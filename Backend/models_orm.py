import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from store import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "User"

    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, unique=True, nullable=False)
    role = Column(String, default="USER")
    createdAt = Column(DateTime, default=datetime.utcnow)
    updatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    targets = relationship("Target", back_populates="user")

class Target(Base):
    __tablename__ = "Target"

    id = Column(String, primary_key=True, default=generate_uuid)
    type = Column(String, nullable=False)  # URL, IP, API
    value = Column(String, nullable=False)
    userId = Column(String, ForeignKey("User.id"), nullable=False)

    verificationToken = Column(String, default=lambda: f"vaptiq-verify={generate_uuid()[:16]}")
    isVerified = Column(Boolean, default=False)
    verifiedAt = Column(DateTime, nullable=True)

    createdAt = Column(DateTime, default=datetime.utcnow)
    updatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="targets")
    scans = relationship("Scan", back_populates="target")

class Scan(Base):
    __tablename__ = "Scan"

    id = Column(String, primary_key=True, default=generate_uuid)
    targetId = Column(String, ForeignKey("Target.id"), nullable=False)
    status = Column(String, default="QUEUED") # QUEUED, RUNNING, COMPLETED, FAILED
    startedAt = Column(DateTime, nullable=True)
    endedAt = Column(DateTime, nullable=True)

    createdAt = Column(DateTime, default=datetime.utcnow)
    updatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    target = relationship("Target", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    logs = relationship("AgentLog", back_populates="scan")

class Vulnerability(Base):
    __tablename__ = "Vulnerability"

    id = Column(String, primary_key=True, default=generate_uuid)
    scanId = Column(String, ForeignKey("Scan.id"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)   # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String, default="SUSPECTED") # SUSPECTED, CONFIRMED, FALSE_POSITIVE
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    proof = Column(Text, nullable=True) # Added proof field as it is used in report

    createdAt = Column(DateTime, default=datetime.utcnow)
    updatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan", back_populates="vulnerabilities")

class AgentLog(Base):
    __tablename__ = "AgentLog"

    id = Column(String, primary_key=True, default=generate_uuid)
    scanId = Column(String, ForeignKey("Scan.id"), nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="logs")
