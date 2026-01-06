# Third-Party Risk Management (TPRM) Module

Enterprise-grade vendor risk assessment workflow utilizing **NIST SP 800-161** (Cybersecurity Supply Chain Risk Management) standards.

## 🎯 Overview

This module provides a comprehensive Third-Party Risk Management (TPRM) workflow for evaluating vendors based on data sensitivity, business criticality, and security control maturity.

## ✨ Features

- **Vendor Tiering**: Automatic classification (Critical, High, Moderate, Low) based on data access and business impact
- **NIST SP 800-161 Alignment**: 27 security controls across 7 domains
- **Risk Scoring**: Inherent risk calculation with residual risk after controls
- **Gap Analysis**: Identifies missing mandatory controls
- **Contract Generation**: Security requirements for vendor agreements
- **Assessment Scheduling**: Tier-based reassessment frequency

## 📊 Assessment Domains

| Domain | Controls | Focus Area |
|--------|----------|------------|
| Governance | 4 | Policies, training, risk management |
| Access Control | 4 | MFA, PAM, access reviews |
| Data Protection | 5 | Encryption, DLP, privacy |
| Security Operations | 4 | Vulnerability mgmt, monitoring |
| Incident Response | 3 | IR plans, breach notification |
| Compliance | 3 | SOC 2, ISO 27001, certifications |
| Business Continuity | 3 | BCP, DR, redundancy |

## 🚀 Usage

```bash
# Run with sample data
python tprm_workflow.py

# Use in your own code
from tprm_workflow import TPRMWorkflow, VendorProfile, DataClassification

# Create workflow engine
tprm = TPRMWorkflow()

# Define vendor
vendor = VendorProfile(
    vendor_id="VND-001",
    vendor_name="Acme Cloud Services",
    vendor_type="SaaS",
    data_classification=DataClassification.RESTRICTED,
    data_types=["PII", "Financial"],
    data_volume="High",
    data_location=["United States"],
    business_criticality="High",
    ...
)

# Run assessment
report = tprm.assess_vendor(vendor, assessment_responses)
```

## 📋 Sample Output

```
======================================================================
         THIRD-PARTY RISK MANAGEMENT ASSESSMENT REPORT
              NIST SP 800-161 Aligned Evaluation
======================================================================

📋 VENDOR PROFILE
----------------------------------------
  Vendor ID:          VND-2024-001
  Vendor Name:        CloudPayroll Solutions Inc.
  Vendor Type:        SaaS
  Risk Tier:          High
  Data Classification: Restricted

📊 RISK ASSESSMENT SCORES
----------------------------------------
  Inherent Risk:        68.0/100
  Control Effectiveness: 82.5%
  Residual Risk:        23.2/100
  Risk Rating:          Low
  Risk Meter: 🟢 [███████░░░░░░░░░░░░░░░░░░░░░░░] 23%

✅ ASSESSMENT RESULT
----------------------------------------
  Status:           ⚠️ Conditionally Approved
  Controls Assessed: 27
  Gaps Identified:   6
  Mandatory Gaps:    1
```

## 🏷️ Vendor Tiering Matrix

| Data Classification | Critical | High | Medium | Low |
|--------------------|----------|------|--------|-----|
| Highly Restricted  | Tier 1   | Tier 1 | Tier 2 | Tier 2 |
| Restricted         | Tier 1   | Tier 2 | Tier 2 | Tier 3 |
| Confidential       | Tier 2   | Tier 2 | Tier 3 | Tier 3 |
| Internal           | Tier 2   | Tier 3 | Tier 3 | Tier 4 |
| Public             | Tier 3   | Tier 3 | Tier 4 | Tier 4 |

## 📅 Assessment Frequency

| Tier | Frequency | Description |
|------|-----------|-------------|
| Critical (Tier 1) | Annual | Full assessment + quarterly check-ins |
| High (Tier 2) | Annual | Full assessment |
| Moderate (Tier 3) | Biennial | Abbreviated assessment |
| Low (Tier 4) | Every 3 years | Self-attestation |

## 📄 Generated Outputs

1. **Assessment Report**: Complete risk evaluation with scores
2. **Gap Analysis**: Missing controls with remediation timelines
3. **Contract Requirements**: Security clauses for vendor agreements
4. **SLA Requirements**: Incident response, patching, reporting SLAs

## 🔗 Framework Alignment

- NIST SP 800-161 (Supply Chain Risk Management)
- ISO 27001:2022 Annex A.15 (Supplier Relationships)
- SOC 2 Trust Services Criteria
- NIST CSF Supply Chain Risk Management (ID.SC)

## 📚 References

- [NIST SP 800-161r1](https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final)
- [ISO 27001:2022 Supplier Security](https://www.iso.org/standard/27001)
