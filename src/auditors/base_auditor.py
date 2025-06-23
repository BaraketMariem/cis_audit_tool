"""
Base auditor class for CIS benchmark checking
"""
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from datetime import datetime

class RuleStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIP = "SKIP"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class AuditResult:
    rule_id: str
    title: str
    description: str
    status: RuleStatus
    severity: Severity
    level: int
    section: str
    details: str
    remediation: Optional[str] = None
    references: Optional[List[str]] = None
    timestamp: str = None
    execution_time: float = 0.0
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

class BaseAuditor(ABC):
    def __init__(self):
        self.results: List[AuditResult] = []
        self.errors: List[str] = []
    
    @abstractmethod
    def audit(self, data: Dict[str, Any]) -> List[AuditResult]:
        """Perform audit and return results"""
        pass
    
    def add_result(self, result: AuditResult):
        """Add audit result"""
        self.results.append(result)
    
    def add_error(self, error: str):
        """Add error message"""
        self.errors.append(error)
    
    def get_summary(self) -> Dict[str, int]:
        """Get audit summary statistics"""
        summary = {
            'total': len(self.results),
            'pass': 0,
            'fail': 0,
            'error': 0,
            'skip': 0,
            'not_applicable': 0
        }
        
        for result in self.results:
            if result.status == RuleStatus.PASS:
                summary['pass'] += 1
            elif result.status == RuleStatus.FAIL:
                summary['fail'] += 1
            elif result.status == RuleStatus.ERROR:
                summary['error'] += 1
            elif result.status == RuleStatus.SKIP:
                summary['skip'] += 1
            elif result.status == RuleStatus.NOT_APPLICABLE:
                summary['not_applicable'] += 1
        
        return summary
    
    def get_compliance_score(self) -> float:
        """Calculate compliance score percentage"""
        summary = self.get_summary()
        total_applicable = summary['pass'] + summary['fail']
        
        if total_applicable == 0:
            return 0.0
        
        return (summary['pass'] / total_applicable) * 100
