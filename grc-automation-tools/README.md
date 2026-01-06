# GRC Automation Tools

Enterprise-grade Python modules for automating GRC (Governance, Risk, and Compliance) workflows. Designed for security practitioners implementing NIST CSF, ISO 27001, SOC 2, and other compliance frameworks.

## Modules

| Module | Description | Framework Reference | Sample Data |
|--------|-------------|---------------------|-------------|
| **Credential Auditor** | Password policy compliance and entropy analysis | NIST SP 800-63B | passwords.sample.txt |
| **Asset Management** | IT asset lifecycle tracking and EOL detection | CIS Controls v8, ISO 27001 A.8 | inventory.sample.csv |
| **Security Log Analyzer** | Real-time threat detection and incident correlation | NIST CSF DE.CM, MITRE ATT&CK | access.sample.log |
| **Vulnerability Management** | CVSS-based prioritization and remediation workflows | CVSS 3.1, NIST CSF ID.RA | findings.sample.json |
| **Compliance Tracker** | Multi-framework control status and gap analysis | NIST CSF, ISO 27001, SOC 2 | controls.sample.json |
| **Risk Register** | Enterprise risk scoring and treatment tracking | ISO 31000, NIST RMF | risks.sample.csv |

## Environment Setup

```bash
cd grc-automation-tools
python -m venv .venv
.venv\Scripts\activate    # Windows
source .venv/bin/activate # Linux/macOS
```

## Usage Examples

### Credential Auditor
```bash
# Single password analysis
python credential-auditor/password_checker.py --password "SecureP@ss123!"

# Batch credential audit
python credential-auditor/password_checker_batch.py --file credential-auditor/passwords.sample.txt
```

### Asset Management
```bash
python asset-management/asset_inventory.py --csv asset-management/inventory.sample.csv --verbose
```

### Security Log Analyzer
```bash
python security-log-analyzer/log_analyzer.py --log security-log-analyzer/access.sample.log --verbose
```

### Vulnerability Management
```bash
python vulnerability-management/vuln_reporter.py --json vulnerability-management/findings.sample.json --verbose
```

### Compliance Tracker
```bash
python compliance-tracker/compliance_dashboard.py --json compliance-tracker/controls.sample.json --verbose
```

### Risk Register
```bash
python risk-register/risk_assessment.py --csv risk-register/risks.sample.csv --verbose
```

## Features

- **No External Dependencies** - Uses Python standard library only for maximum portability
- **Enterprise Sample Data** - Each module includes realistic enterprise-grade sample data
- **CLI Interface** - Run any script with `-h` for usage information
- **Export Options** - Several modules support CSV export for SIEM/GRC tool integration
- **Framework Alignment** - All modules map to recognized security frameworks
