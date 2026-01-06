# GRC Automation Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![NIST CSF](https://img.shields.io/badge/Framework-NIST%20CSF-green.svg)](https://www.nist.gov/cyberframework)
[![ISO 27001](https://img.shields.io/badge/Framework-ISO%2027001-blue.svg)](https://www.iso.org/isoiec-27001-information-security.html)

Enterprise-grade GRC (Governance, Risk, and Compliance) automation toolkit designed for security practitioners. Implements industry-standard frameworks including NIST CSF, NIST SP 800-63B, ISO 27001, SOC 2, and CIS Benchmarks.

## Overview

This toolkit provides production-ready automation modules for:
- **Credential Auditing** - NIST SP 800-63B password strength analysis and policy enforcement
- **Asset Management** - IT asset tracking, lifecycle management, and EOL detection
- **Security Log Analysis** - Real-time threat detection and incident correlation
- **Vulnerability Management** - CVSS-based prioritization and remediation workflows
- **Compliance Tracking** - Multi-framework control status and gap analysis (NIST CSF, ISO 27001, SOC 2)
- **Risk Register** - Quantitative risk scoring, treatment tracking, and executive reporting
- **Vendor Risk Management** - NIST SP 800-161 aligned third-party risk assessment (TPRM)
- **AWS Security Labs** - Cloud security implementations and hands-on exercises
- **Compliance Platform** - Vanta-style FastAPI backend for continuous compliance automation

## Repository Structure

```
GRC-Automation-Toolkit/
├── grc-automation-tools/        # Core automation modules
│   ├── credential-auditor/      # Password policy compliance
│   ├── asset-management/        # IT asset lifecycle tracking
│   ├── security-log-analyzer/   # Threat detection engine
│   ├── vulnerability-management/# CVSS-based prioritization
│   ├── compliance-tracker/      # Framework control mapping
│   ├── risk-register/           # Enterprise risk management
│   └── vendor-risk-management/  # NIST SP 800-161 TPRM workflow
├── compliance-platform/         # FastAPI compliance SaaS backend
├── grc-compliance-monitor/      # AWS security labs
│   └── AWS-Labs/
│       ├── Lab-01-Shared-Responsibility/
│       ├── Lab-02-IAM-Security/
│       ├── Lab-03-CICD-Security/
│       ├── Lab-04-Workload-Hardening/
│       ├── Lab-05-Security-Monitoring/
│       ├── Lab-06-Threat-Detection/
│       ├── Lab-07-Incident-Response/
│       └── Lab-08-Zero-Trust/
├── tests/                       # pytest test suite
└── email-security-project/      # Email security controls
```

## Quick Start

### Prerequisites
- Python 3.9 or higher
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/osayande-infosec/GRC-Automation-Toolkit.git
cd GRC-Automation-Toolkit

# Set up Python environment (recommended)
cd grc-automation-tools
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate
```

### Running the Automation Modules

```bash
# Credential auditing - single password
python credential-auditor/password_checker.py --password "YourP@ssw0rd!"

# Credential auditing - batch audit
python credential-auditor/password_checker_batch.py --file credential-auditor/passwords.sample.txt

# Asset management - inventory analysis
python asset-management/asset_inventory.py --csv asset-management/inventory.sample.csv

# Security log analysis - threat detection
python security-log-analyzer/log_analyzer.py --log security-log-analyzer/access.sample.log --verbose

# Vulnerability management - prioritization report
python vulnerability-management/vuln_reporter.py --json vulnerability-management/findings.sample.json

# Compliance tracking - framework status
python compliance-tracker/compliance_dashboard.py --json compliance-tracker/controls.sample.json

# Risk register - risk assessment report
python risk-register/risk_assessment.py --csv risk-register/risks.sample.csv --verbose
```

## Module Reference

| Module | Purpose | Framework Reference | Input Format |
|--------|---------|---------------------|--------------|
| Credential Auditor | Password policy compliance | NIST SP 800-63B | String/TXT |
| Asset Management | IT asset lifecycle tracking | CIS Controls v8, ISO 27001 | CSV |
| Security Log Analyzer | Threat detection engine | NIST CSF DE.CM | Apache/Syslog |
| Vulnerability Management | Remediation prioritization | CVSS 3.1, NIST CSF ID.RA | JSON |
| Compliance Tracker | Control status mapping | NIST CSF, ISO 27001, SOC 2 | JSON |
| Risk Register | Enterprise risk management | ISO 31000, NIST RMF | CSV |

## Sample Output

### Credential Auditor
```
==================================================
Password Assessment Results
==================================================
Score:    70/100
Verdict:  Strong
Entropy:  36.05 bits

Findings:
  • Length OK (11 chars). Consider 12+ for better security.
  • Good character diversity (4/4 classes).
  • Moderate entropy (36.1 bits).
==================================================
```

### Asset Management
```
============================================================
ASSET INVENTORY REPORT
============================================================

📊 SUMMARY
   Total Assets: 25
   Compliance Rate: 80.0%

📁 BY TYPE:
   • Server: 13
   • Network: 5
   • Workstation: 5

🔔 ALERTS:
   ⚠️  2 asset(s) past end-of-life
   ⚠️  4 asset(s) not updated in 90+ days
   🚨 4 non-compliant asset(s)
============================================================
```

### Security Log Analyzer
```
============================================================
SECURITY LOG ANALYSIS REPORT
============================================================

🚨 SECURITY ALERTS (7)
   🟠 [HIGH] Brute Force: 1 IP(s) with 10+ failed auth attempts
   🟠 [HIGH] Shell Injection: 12 request(s) detected
   🟡 [MEDIUM] Path Traversal: 1 request(s) detected
   🟡 [MEDIUM] Scanner Detected: 2 IP(s) using known scanner tools
   🟡 [MEDIUM] XSS Attempt: 1 request(s) detected

📈 STATUS CODE DISTRIBUTION
      200: 13 (37.1%)
   ⚠️ 401: 11 (31.4%) - Failed authentication attempts
   ⚠️ 403: 2 (5.7%)   - Forbidden access attempts
============================================================
```

### Vulnerability Management
```
============================================================
VULNERABILITY ASSESSMENT REPORT
============================================================

🔴 OVERALL RISK SCORE: 100/100

📊 SUMMARY
   Total Findings: 10
   Unique Vulnerabilities: 10
   Affected Assets: 6

🎯 BY SEVERITY
   🔴 Critical: 2
   🟠 High: 3
   🟡 Medium: 3

🚨 CRITICAL FINDINGS (2)
   • Apache HTTP Server Remote Code Execution (CVSS: 9.8)
   • SMBv1 Protocol Enabled (CVSS: 9.3)
============================================================
```

### Compliance Tracker
```
============================================================
COMPLIANCE DASHBOARD
Framework: NIST Cybersecurity Framework
============================================================

🟡 COMPLIANCE SCORE: 71.9% - PARTIAL COMPLIANCE
   [██████████████░░░░░░]

📊 CONTROL STATUS SUMMARY
   ✅ Implemented: 9 (56.2%)
   ❌ Not Implemented: 2 (12.5%)
   🔶 Partial: 5 (31.2%)

📁 BY CONTROL FAMILY
   • Detect: 3/3 implemented (100%)
   • Identify: 3/4 implemented (75%)
   • Protect: 3/5 implemented (60%)
   • Recover: 0/2 implemented (0%)
   • Respond: 0/2 implemented (0%)
============================================================
```

### Risk Register
```
============================================================
RISK ASSESSMENT REPORT
============================================================

📈 RISK METRICS
   Total Risks: 15
   Average Inherent Score: 12.1/25
   Average Residual Score: 5.6/25
   Risk Reduction: 53.8%

🎯 RISK DISTRIBUTION
   🔴 Critical: 2 (13.3%)
   🟠 High: 7 (46.7%)
   🟡 Medium: 6 (40.0%)

🚨 CRITICAL RISKS (2)
   • Ransomware Attack (Score: 20 → 8)
   • Legacy System Compromise (Score: 20 → 12)
============================================================
```

## AWS Security Labs

The `grc-compliance-monitor/AWS-Labs/` directory contains enterprise cloud security exercises:

1. **Shared Responsibility Model** - Understanding AWS vs. customer security ownership
2. **IAM Security** - Least privilege implementation, MFA enforcement, and access analysis
3. **CI/CD Security** - Secure pipelines with SAST/DAST integration
4. **Workload Hardening** - CIS Benchmarks for EC2, containers, and Lambda
5. **Security Monitoring** - CloudTrail, CloudWatch, and VPC Flow Logs analysis
6. **Threat Detection** - GuardDuty, Inspector, and Macie implementation
7. **Incident Response** - IR playbooks and automated containment procedures
8. **Zero Trust Architecture** - Identity-centric, micro-segmented network design

## Professional Development Path

1. **Foundation** - Run automation modules with sample data to understand output formats
2. **Customization** - Adapt scripts to your organization's compliance requirements
3. **Integration** - Connect modules to your SIEM, ticketing, and CMDB systems
4. **Cloud Security** - Complete AWS labs for cloud-native security implementation
5. **Orchestration** - Build automated compliance workflows combining multiple modules

## Use Cases

- **Audit Preparation** - Generate compliance evidence and control documentation
- **Risk Reporting** - Executive dashboards and board-level risk metrics
- **Vulnerability Triage** - CVSS-based prioritization for remediation teams
- **Credential Hygiene** - Enterprise password policy enforcement
- **Asset Lifecycle** - EOL tracking and procurement planning

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**osayande-infosec** - CISSP, Security Practitioner

---

⭐ If you find this toolkit useful for your GRC automation needs, please star the repository!
