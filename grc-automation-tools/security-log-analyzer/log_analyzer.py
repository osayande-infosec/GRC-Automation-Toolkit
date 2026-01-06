#!/usr/bin/env python3
"""
Log Analyzer Module
-------------------
GRC Automation Toolkit - Module 03

Analyzes security logs for suspicious patterns and anomalies:
- Failed authentication attempts
- Unusual access patterns
- IP-based threat detection
- Time-based anomaly detection
- Summary statistics and alerts

Supports common log formats (Apache, auth.log style).

Author: osayande-infosec
License: MIT
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple


# Suspicious patterns to detect
SUSPICIOUS_PATTERNS = {
    "sql_injection": re.compile(r"(union\s+select|or\s+1=1|drop\s+table|--\s*$)", re.I),
    "xss_attempt": re.compile(r"(<script|javascript:|onerror=|onload=)", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),
    "shell_injection": re.compile(r"(;|\||&|\$\(|`)", re.I),
    "scanner_ua": re.compile(r"(nikto|sqlmap|nmap|masscan|burp|zap)", re.I),
}

# HTTP status codes of interest
ERROR_STATUS_CODES = {"400", "401", "403", "404", "405", "500", "502", "503"}
AUTH_FAILURE_CODES = {"401", "403"}


@dataclass
class LogEntry:
    """Parsed log entry."""
    timestamp: Optional[datetime]
    ip_address: str
    method: str
    path: str
    status_code: str
    user_agent: str
    raw_line: str
    user: str = ""


@dataclass
class SecurityAlert:
    """Security alert from log analysis."""
    severity: str  # critical, high, medium, low, info
    category: str
    message: str
    count: int = 1
    sample_ips: List[str] = field(default_factory=list)


@dataclass
class LogReport:
    """Analysis report."""
    total_entries: int
    unique_ips: int
    time_range: Tuple[Optional[datetime], Optional[datetime]]
    status_distribution: Dict[str, int]
    top_paths: List[Tuple[str, int]]
    top_ips: List[Tuple[str, int]]
    alerts: List[SecurityAlert]
    failed_auth_by_ip: Dict[str, int]
    suspicious_requests: List[Tuple[str, str, str]]  # (ip, path, pattern_type)


def parse_apache_log(line: str) -> Optional[LogEntry]:
    """Parse Apache/NCSA combined log format."""
    # Pattern: IP - - [timestamp] "METHOD /path HTTP/x.x" status size "referer" "user-agent"
    pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d{3}) \S+ "[^"]*" "([^"]*)"'
    match = re.match(pattern, line)
    
    if match:
        ip, timestamp_str, method, path, status, user_agent = match.groups()
        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                timestamp = datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                timestamp = None
        
        return LogEntry(
            timestamp=timestamp,
            ip_address=ip,
            method=method,
            path=path.split()[0] if path else "",
            status_code=status,
            user_agent=user_agent,
            raw_line=line,
        )
    return None


def parse_auth_log(line: str) -> Optional[LogEntry]:
    """Parse auth.log style entries."""
    # Pattern: timestamp hostname service[pid]: message
    failed_pattern = r'(\w+\s+\d+\s+[\d:]+).*Failed password for (?:invalid user )?(\S+) from (\S+)'
    match = re.search(failed_pattern, line)
    
    if match:
        timestamp_str, user, ip = match.groups()
        return LogEntry(
            timestamp=None,  # Simplified; would need year context
            ip_address=ip,
            method="AUTH",
            path="",
            status_code="401",
            user_agent="",
            raw_line=line,
            user=user,
        )
    return None


def parse_log_line(line: str) -> Optional[LogEntry]:
    """Try to parse log line with multiple formats."""
    line = line.strip()
    if not line:
        return None
    
    # Try Apache format first
    entry = parse_apache_log(line)
    if entry:
        return entry
    
    # Try auth.log format
    entry = parse_auth_log(line)
    if entry:
        return entry
    
    return None


def detect_suspicious_patterns(entry: LogEntry) -> List[Tuple[str, str]]:
    """Detect suspicious patterns in request."""
    findings = []
    
    text_to_check = f"{entry.path} {entry.user_agent}"
    
    for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(text_to_check):
            findings.append((pattern_name, entry.path))
    
    return findings


def analyze_logs(entries: List[LogEntry]) -> LogReport:
    """Analyze parsed log entries."""
    alerts = []
    
    # Basic statistics
    status_dist = Counter(e.status_code for e in entries)
    ip_counts = Counter(e.ip_address for e in entries)
    path_counts = Counter(e.path for e in entries if e.path)
    
    # Track failed auth by IP
    failed_auth_by_ip = Counter(
        e.ip_address for e in entries 
        if e.status_code in AUTH_FAILURE_CODES
    )
    
    # Detect brute force attempts (>10 failures from same IP)
    brute_force_ips = [ip for ip, count in failed_auth_by_ip.items() if count >= 10]
    if brute_force_ips:
        alerts.append(SecurityAlert(
            severity="high",
            category="Brute Force",
            message=f"{len(brute_force_ips)} IP(s) with 10+ failed auth attempts",
            count=len(brute_force_ips),
            sample_ips=brute_force_ips[:5],
        ))
    
    # Detect suspicious patterns
    suspicious_requests = []
    pattern_counts = defaultdict(int)
    
    for entry in entries:
        findings = detect_suspicious_patterns(entry)
        for pattern_type, path in findings:
            suspicious_requests.append((entry.ip_address, path, pattern_type))
            pattern_counts[pattern_type] += 1
    
    for pattern_type, count in pattern_counts.items():
        severity = "high" if pattern_type in ("sql_injection", "shell_injection") else "medium"
        alerts.append(SecurityAlert(
            severity=severity,
            category=pattern_type.replace("_", " ").title(),
            message=f"{count} request(s) matching {pattern_type} pattern",
            count=count,
        ))
    
    # High error rate detection
    total = len(entries)
    error_count = sum(count for code, count in status_dist.items() if code in ERROR_STATUS_CODES)
    if total > 0 and (error_count / total) > 0.3:
        alerts.append(SecurityAlert(
            severity="medium",
            category="Error Rate",
            message=f"High error rate: {error_count}/{total} ({error_count/total*100:.1f}%)",
            count=error_count,
        ))
    
    # Scanner detection
    scanner_ips = set()
    for entry in entries:
        if SUSPICIOUS_PATTERNS["scanner_ua"].search(entry.user_agent):
            scanner_ips.add(entry.ip_address)
    
    if scanner_ips:
        alerts.append(SecurityAlert(
            severity="medium",
            category="Scanner Detected",
            message=f"{len(scanner_ips)} IP(s) using known scanner tools",
            count=len(scanner_ips),
            sample_ips=list(scanner_ips)[:5],
        ))
    
    # Time range
    timestamps = [e.timestamp for e in entries if e.timestamp]
    time_range = (min(timestamps), max(timestamps)) if timestamps else (None, None)
    
    return LogReport(
        total_entries=len(entries),
        unique_ips=len(ip_counts),
        time_range=time_range,
        status_distribution=dict(status_dist),
        top_paths=path_counts.most_common(10),
        top_ips=ip_counts.most_common(10),
        alerts=sorted(alerts, key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(a.severity, 5)),
        failed_auth_by_ip=dict(failed_auth_by_ip),
        suspicious_requests=suspicious_requests[:20],
    )


def print_report(report: LogReport, verbose: bool = False) -> None:
    """Print formatted analysis report."""
    print("\n" + "=" * 60)
    print("SECURITY LOG ANALYSIS REPORT")
    print("=" * 60)
    
    print(f"\n📊 OVERVIEW")
    print(f"   Total Entries: {report.total_entries:,}")
    print(f"   Unique IPs: {report.unique_ips:,}")
    if report.time_range[0]:
        print(f"   Time Range: {report.time_range[0]} to {report.time_range[1]}")
    
    # Alerts section (most important)
    if report.alerts:
        print(f"\n🚨 SECURITY ALERTS ({len(report.alerts)})")
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for alert in report.alerts:
            icon = severity_icons.get(alert.severity, "⚪")
            print(f"   {icon} [{alert.severity.upper()}] {alert.category}: {alert.message}")
            if alert.sample_ips:
                print(f"      Sample IPs: {', '.join(alert.sample_ips[:3])}")
    else:
        print(f"\n✅ No security alerts detected")
    
    print(f"\n📈 STATUS CODE DISTRIBUTION")
    for code, count in sorted(report.status_distribution.items()):
        pct = count / report.total_entries * 100 if report.total_entries else 0
        marker = "⚠️ " if code in ERROR_STATUS_CODES else "   "
        print(f"   {marker}{code}: {count:,} ({pct:.1f}%)")
    
    if verbose:
        print(f"\n🔝 TOP 10 REQUESTED PATHS")
        for path, count in report.top_paths:
            print(f"   • {path}: {count:,}")
        
        print(f"\n🌐 TOP 10 SOURCE IPs")
        for ip, count in report.top_ips:
            print(f"   • {ip}: {count:,}")
        
        if report.suspicious_requests:
            print(f"\n🔍 SUSPICIOUS REQUESTS (sample)")
            for ip, path, pattern in report.suspicious_requests[:10]:
                print(f"   • [{pattern}] {ip}: {path[:50]}")
    
    print("\n" + "=" * 60 + "\n")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze security logs for threats and anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py --log access.log
  python log_analyzer.py --log /var/log/auth.log --verbose
        """
    )
    parser.add_argument(
        "--log", "-l",
        required=True,
        type=Path,
        help="Path to log file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed analysis"
    )
    
    args = parser.parse_args()
    
    if not args.log.exists():
        raise SystemExit(f"File not found: {args.log}")
    
    print(f"Parsing {args.log}...")
    
    entries = []
    with args.log.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            entry = parse_log_line(line)
            if entry:
                entries.append(entry)
    
    if not entries:
        raise SystemExit("No valid log entries found. Check log format.")
    
    print(f"Analyzing {len(entries):,} entries...")
    report = analyze_logs(entries)
    print_report(report, verbose=args.verbose)


if __name__ == "__main__":
    main()
