"""
Security Log Analysis API Endpoints
-----------------------------------
Real-time threat detection and incident correlation.
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel, Field
import re

from app.core.security import get_current_user, TokenData

router = APIRouter()


class LogEntry(BaseModel):
    """Parsed log entry."""
    timestamp: Optional[str]
    source_ip: str
    method: Optional[str]
    path: str
    status_code: int
    size: Optional[int]
    user_agent: Optional[str]


class SecurityAlert(BaseModel):
    """Security alert from log analysis."""
    severity: str  # critical, high, medium, low
    alert_type: str
    description: str
    source_ips: List[str]
    count: int
    sample_requests: List[str]


class LogAnalysisResult(BaseModel):
    """Log analysis result."""
    total_entries: int
    unique_ips: int
    time_range: Optional[dict]
    alerts: List[SecurityAlert]
    status_distribution: dict
    top_paths: List[dict]
    top_ips: List[dict]
    suspicious_requests: List[dict]


class LogAnalysisRequest(BaseModel):
    """Log analysis request with raw log data."""
    log_data: str = Field(..., description="Raw log data (Apache/Nginx format)")


# Threat detection patterns
SUSPICIOUS_PATTERNS = {
    "path_traversal": r"\.\./|\.\.\\",
    "sql_injection": r"('|\"|\s)(or|and|union|select|insert|update|delete|drop)\s",
    "xss_attempt": r"<script|javascript:|on\w+\s*=",
    "shell_injection": r";\s*(ls|cat|rm|wget|curl|bash|sh|nc)\s",
    "scanner_ua": r"nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz",
}

# Apache Combined Log Format regex
APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+[^"]*"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+|-)\s+'
    r'"[^"]*"\s+"(?P<ua>[^"]*)"'
)


def parse_log_line(line: str) -> Optional[LogEntry]:
    """Parse a single log line."""
    match = APACHE_LOG_PATTERN.match(line.strip())
    if match:
        return LogEntry(
            timestamp=match.group("timestamp"),
            source_ip=match.group("ip"),
            method=match.group("method"),
            path=match.group("path"),
            status_code=int(match.group("status")),
            size=int(match.group("size")) if match.group("size") != "-" else None,
            user_agent=match.group("ua"),
        )
    return None


def detect_threats(entries: List[LogEntry]) -> List[SecurityAlert]:
    """Detect security threats in log entries."""
    alerts = []
    
    # Brute force detection (10+ failed auth from same IP)
    failed_auth = {}
    for entry in entries:
        if entry.status_code == 401:
            failed_auth[entry.source_ip] = failed_auth.get(entry.source_ip, 0) + 1
    
    brute_force_ips = [ip for ip, count in failed_auth.items() if count >= 10]
    if brute_force_ips:
        alerts.append(SecurityAlert(
            severity="high",
            alert_type="brute_force",
            description=f"{len(brute_force_ips)} IP(s) with 10+ failed authentication attempts",
            source_ips=brute_force_ips[:10],
            count=len(brute_force_ips),
            sample_requests=[],
        ))
    
    # Pattern-based detection
    for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
        matches = []
        source_ips = set()
        for entry in entries:
            search_text = f"{entry.path} {entry.user_agent or ''}"
            if re.search(pattern, search_text, re.IGNORECASE):
                matches.append(f"{entry.source_ip}: {entry.path[:80]}")
                source_ips.add(entry.source_ip)
        
        if matches:
            severity = "high" if pattern_name in ("sql_injection", "shell_injection") else "medium"
            alerts.append(SecurityAlert(
                severity=severity,
                alert_type=pattern_name,
                description=f"{len(matches)} request(s) matching {pattern_name.replace('_', ' ')} pattern",
                source_ips=list(source_ips)[:10],
                count=len(matches),
                sample_requests=matches[:5],
            ))
    
    # High error rate detection
    error_count = sum(1 for e in entries if e.status_code >= 400)
    if entries and error_count / len(entries) > 0.3:
        alerts.append(SecurityAlert(
            severity="medium",
            alert_type="high_error_rate",
            description=f"High error rate: {error_count}/{len(entries)} ({error_count/len(entries)*100:.1f}%)",
            source_ips=[],
            count=error_count,
            sample_requests=[],
        ))
    
    return alerts


@router.post("/analyze", response_model=LogAnalysisResult)
async def analyze_logs(
    request: LogAnalysisRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Analyze security logs for threats and anomalies.
    
    Detects:
    - Brute force attacks
    - SQL injection attempts
    - XSS attempts
    - Path traversal
    - Scanner activity
    - Shell injection
    """
    lines = request.log_data.strip().split("\n")
    entries = []
    
    for line in lines:
        if line.strip() and not line.startswith("#"):
            entry = parse_log_line(line)
            if entry:
                entries.append(entry)
    
    if not entries:
        raise HTTPException(status_code=400, detail="No valid log entries found")
    
    # Detect threats
    alerts = detect_threats(entries)
    
    # Status code distribution
    status_dist = {}
    for entry in entries:
        status_dist[str(entry.status_code)] = status_dist.get(str(entry.status_code), 0) + 1
    
    # Top paths
    path_counts = {}
    for entry in entries:
        path_counts[entry.path] = path_counts.get(entry.path, 0) + 1
    top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Top IPs
    ip_counts = {}
    for entry in entries:
        ip_counts[entry.source_ip] = ip_counts.get(entry.source_ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Suspicious requests sample
    suspicious = []
    for alert in alerts:
        for req in alert.sample_requests[:3]:
            suspicious.append({
                "type": alert.alert_type,
                "request": req,
            })
    
    return LogAnalysisResult(
        total_entries=len(entries),
        unique_ips=len(set(e.source_ip for e in entries)),
        time_range={
            "start": entries[0].timestamp if entries else None,
            "end": entries[-1].timestamp if entries else None,
        },
        alerts=alerts,
        status_distribution=status_dist,
        top_paths=[{"path": p, "count": c} for p, c in top_paths],
        top_ips=[{"ip": ip, "count": c} for ip, c in top_ips],
        suspicious_requests=suspicious[:20],
    )


@router.post("/analyze/file", response_model=LogAnalysisResult)
async def analyze_log_file(
    file: UploadFile = File(...),
    current_user: TokenData = Depends(get_current_user),
):
    """
    Analyze an uploaded log file.
    
    Accepts: .log, .txt files (max 10MB)
    """
    if not file.filename.endswith((".log", ".txt")):
        raise HTTPException(status_code=400, detail="Only .log and .txt files accepted")
    
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    
    log_data = content.decode("utf-8", errors="ignore")
    
    request = LogAnalysisRequest(log_data=log_data)
    return await analyze_logs(request, current_user)


@router.get("/patterns")
async def get_detection_patterns():
    """Get list of threat detection patterns."""
    return {
        "patterns": [
            {
                "name": "path_traversal",
                "description": "Directory traversal attempts (../ patterns)",
                "severity": "medium",
            },
            {
                "name": "sql_injection",
                "description": "SQL injection keywords in requests",
                "severity": "high",
            },
            {
                "name": "xss_attempt",
                "description": "Cross-site scripting payloads",
                "severity": "medium",
            },
            {
                "name": "shell_injection",
                "description": "Shell command injection attempts",
                "severity": "high",
            },
            {
                "name": "scanner_ua",
                "description": "Known security scanner user agents",
                "severity": "medium",
            },
            {
                "name": "brute_force",
                "description": "Multiple failed authentication attempts",
                "severity": "high",
            },
        ]
    }
