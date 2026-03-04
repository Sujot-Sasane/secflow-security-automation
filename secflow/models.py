from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any

Severity = Literal["info", "low", "medium", "high", "critical"]

class Finding(BaseModel):
    tool: str
    rule_id: str
    severity: Severity = "info"
    title: str
    file: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    confidence: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class Report(BaseModel):
    generated_at: str
    target: str
    findings: List[Finding] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)
