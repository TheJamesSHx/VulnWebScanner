"""Database models and operations using SQLAlchemy."""

from datetime import datetime
from typing import Dict, List, Optional, Any
import json
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from loguru import logger
import os

Base = declarative_base()


class Scan(Base):
    """Scan record model."""
    
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(500), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(50), default='pending')  # pending, running, completed, failed, stopped
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    config = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'error': self.error
        }


class ScanResult(Base):
    """Scan result model."""
    
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, nullable=False)
    module = Column(String(100), nullable=False)
    vulnerability_type = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=True)  # critical, high, medium, low, info
    confidence = Column(Float, default=1.0)  # 0.0 to 1.0
    url = Column(String(1000), nullable=True)
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    results = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    cvss_score = Column(Float, nullable=True)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'module': self.module,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'url': self.url,
            'payload': self.payload,
            'evidence': self.evidence,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'cvss_score': self.cvss_score
        }


class Database:
    """Database handler for scan storage and retrieval."""
    
    def __init__(self, config: Dict):
        """Initialize database connection.
        
        Args:
            config: Database configuration
        """
        self.config = config
        self.engine = None
        self.Session = None
        self._init_database()
    
    def _init_database(self):
        """Initialize database engine and create tables."""
        db_path = self.config.get('path', 'data/scanner.db')
        
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Create engine
        if self.config['engine'] == 'sqlite':
            db_url = f"sqlite:///{db_path}"
        elif self.config['engine'] == 'postgresql':
            db_url = f"postgresql://{self.config['user']}:{self.config['password']}@{self.config['host']}/{self.config['database']}"
        else:
            db_url = f"sqlite:///data/scanner.db"
        
        self.engine = create_engine(
            db_url,
            pool_size=self.config.get('pool_size', 10),
            max_overflow=self.config.get('max_overflow', 20),
            echo=self.config.get('echo', False)
        )
        
        # Create tables
        Base.metadata.create_all(self.engine)
        
        # Create session factory
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        
        logger.info(f"Database initialized: {db_url}")
    
    def create_scan(self, scan: Scan) -> int:
        """Create a new scan record.
        
        Args:
            scan: Scan object
            
        Returns:
            Scan ID
        """
        session = self.Session()
        try:
            session.add(scan)
            session.commit()
            scan_id = scan.id
            logger.debug(f"Scan created: ID={scan_id}")
            return scan_id
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create scan: {str(e)}")
            raise
        finally:
            session.close()
    
    def update_scan_status(self, scan_id: int, status: str, error: Optional[str] = None):
        """Update scan status.
        
        Args:
            scan_id: Scan ID
            status: New status
            error: Error message if failed
        """
        session = self.Session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status = status
                if status in ['completed', 'failed', 'stopped']:
                    scan.end_time = datetime.utcnow()
                if error:
                    scan.error = error
                session.commit()
                logger.debug(f"Scan {scan_id} status updated: {status}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update scan status: {str(e)}")
            raise
        finally:
            session.close()
    
    def save_result(self, result: ScanResult):
        """Save scan result.
        
        Args:
            result: ScanResult object
        """
        session = self.Session()
        try:
            session.add(result)
            session.commit()
            logger.debug(f"Result saved for scan {result.scan_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save result: {str(e)}")
            raise
        finally:
            session.close()
    
    def get_scan(self, scan_id: int) -> Optional[Dict]:
        """Get scan by ID.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Scan dictionary or None
        """
        session = self.Session()
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            return scan.to_dict() if scan else None
        finally:
            session.close()
    
    def get_results(self, scan_id: int) -> List[Dict]:
        """Get all results for a scan.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            List of result dictionaries
        """
        session = self.Session()
        try:
            results = session.query(ScanResult).filter_by(scan_id=scan_id).all()
            return [r.to_dict() for r in results]
        finally:
            session.close()
    
    def list_scans(self, limit: int = 50) -> List[Dict]:
        """List recent scans.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of scan dictionaries
        """
        session = self.Session()
        try:
            scans = session.query(Scan).order_by(Scan.start_time.desc()).limit(limit).all()
            return [s.to_dict() for s in scans]
        finally:
            session.close()


def init_db(config_path: str = "config/scanner_config.yaml") -> Database:
    """Initialize database from config file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Database instance
    """
    import yaml
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return Database(config['database'])