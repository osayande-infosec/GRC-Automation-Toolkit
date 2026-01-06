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
- **AWS Security Labs** - Cloud security implementations and hands-on exercises

## Repository Structure

```
GRC-Automation-Toolkit/
├── grc-automation-tools/        # Core automation modules
│   ├── credential-auditor/      # Password policy compliance
│   ├── asset-management/        # IT asset lifecycle tracking
│   ├── security-log-analyzer/   # Threat detection engine
│   ├── vulnerability-management/# CVSS-based prioritization
│   ├── compliance-tracker/      # Framework control mapping
│   └── risk-register/           # Enterprise risk management
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
