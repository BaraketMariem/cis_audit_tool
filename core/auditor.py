"""
Core Auditor - Base class for all CIS checks
"""
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Any
from datetime import datetime

class CheckStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIP = "SKIP"

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class CheckResult:
    rule_id: str
    title: str
    status: CheckStatus
    severity: Severity
    details: str
    remediation: str = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

class BaseAuditor(ABC):
    def __init__(self):
        self.results: List[CheckResult] = []
    
    @abstractmethod
    def check(self, data: Dict[str, Any]) -> CheckResult:
        """Perform the CIS check"""
        pass
    
    def add_result(self, result: CheckResult):
        self.results.append(result)
