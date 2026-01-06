# Lab 01: AWS Shared Responsibility Model

## Objective
Understand the AWS Shared Responsibility Model and identify security controls owned by AWS vs. the customer.

## Learning Outcomes
- Define the boundary between AWS and customer security responsibilities
- Map common GRC controls to responsibility owners
- Identify compliance implications for different AWS service types

## Key Concepts

### AWS Responsibility ("Security OF the Cloud")
- Physical data center security
- Hardware and infrastructure
- Network infrastructure
- Hypervisor and virtualization layer

### Customer Responsibility ("Security IN the Cloud")
- Identity and Access Management (IAM)
- Data encryption (at rest and in transit)
- Network configuration (Security Groups, NACLs)
- Operating system patches and updates
- Application security

## Hands-On Exercise

### Step 1: Review Service Types
Categorize these AWS services by responsibility model type:
- **IaaS** (EC2): Customer manages OS, patching, apps
- **PaaS** (RDS): AWS manages OS, customer manages data
- **SaaS** (S3): AWS manages most, customer manages access

### Step 2: Control Mapping
For each control domain, identify the responsible party:

| Control | AWS | Customer | Shared |
|---------|-----|----------|--------|
| Physical access | ✓ | | |
| Network segmentation | | ✓ | |
| Data classification | | ✓ | |
| Encryption key management | | | ✓ |
| Patch management (EC2) | | ✓ | |
| Patch management (RDS) | ✓ | | |

### Step 3: Compliance Checklist
Review your AWS environment against these checkpoints:
- [ ] IAM policies follow least privilege
- [ ] S3 buckets have appropriate access controls
- [ ] CloudTrail is enabled for audit logging
- [ ] VPC flow logs are configured
- [ ] Encryption is enabled for data at rest

## Resources
- [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
