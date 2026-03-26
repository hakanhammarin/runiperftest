"""
SQLAlchemy models and database helpers.
"""

from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime,
    Boolean, ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from server.config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Host(Base):
    __tablename__ = "hosts"

    id        = Column(Integer, primary_key=True, index=True)
    hostname  = Column(String, unique=True, nullable=False, index=True)
    os_type   = Column(String, nullable=False)          # "windows" | "linux"
    ip        = Column(String)
    last_seen = Column(DateTime, default=datetime.utcnow)
    online    = Column(Boolean, default=True)

    sessions  = relationship("Session", back_populates="host_rel", foreign_keys="Session.hostname", primaryjoin="Host.hostname == Session.hostname")
    rules     = relationship("FirewallRule", back_populates="host_rel", foreign_keys="FirewallRule.hostname", primaryjoin="Host.hostname == FirewallRule.hostname")


class Session(Base):
    """An observed network 5-tuple reported by an agent."""
    __tablename__ = "sessions"

    id            = Column(Integer, primary_key=True, index=True)
    hostname      = Column(String, ForeignKey("hosts.hostname"), nullable=False, index=True)
    first_seen    = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen     = Column(DateTime, default=datetime.utcnow, nullable=False)
    hit_count     = Column(Integer, default=1)

    protocol      = Column(String, nullable=False)    # tcp | udp
    src_ip        = Column(String, nullable=False)
    src_port      = Column(Integer, nullable=False)
    dst_ip        = Column(String, nullable=False)
    dst_port      = Column(Integer, nullable=False)
    direction     = Column(String, default="out")     # in | out
    state         = Column(String)                    # ESTABLISHED | LISTEN | etc.
    process       = Column(String)                    # optional process name

    # Review state: pending | approved | denied
    review_status = Column(String, default="pending", index=True)
    reviewed_at   = Column(DateTime)
    reviewed_by   = Column(String)

    rule_id       = Column(Integer, ForeignKey("firewall_rules.id"), nullable=True)

    host_rel = relationship("Host", foreign_keys=[hostname], primaryjoin="Host.hostname == Session.hostname")
    rule     = relationship("FirewallRule", foreign_keys=[rule_id])

    __table_args__ = (
        UniqueConstraint("hostname", "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
                         name="uq_session_tuple"),
    )


class FirewallRule(Base):
    """An approved firewall rule ready for distribution."""
    __tablename__ = "firewall_rules"

    id          = Column(Integer, primary_key=True, index=True)
    guid        = Column(String, unique=True, nullable=False, index=True)  # RFC 4122 UUID
    hostname    = Column(String, ForeignKey("hosts.hostname"), nullable=False, index=True)

    name        = Column(String, nullable=False)
    direction   = Column(String, nullable=False)   # in | out
    action      = Column(String, nullable=False)   # allow | deny
    protocol    = Column(String, nullable=False)   # tcp | udp | any
    src_ip      = Column(String)
    src_port    = Column(String)
    dst_ip      = Column(String)
    dst_port    = Column(String)

    # Status: pending | deploying | deployed | revoked | error
    status      = Column(String, default="pending", index=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
    deployed_at = Column(DateTime)
    revoked_at  = Column(DateTime)
    error_msg   = Column(String)

    # Link back to source session
    session_id  = Column(Integer, ForeignKey("sessions.id"), nullable=True)

    host_rel    = relationship("Host", foreign_keys=[hostname], primaryjoin="Host.hostname == FirewallRule.hostname")


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
