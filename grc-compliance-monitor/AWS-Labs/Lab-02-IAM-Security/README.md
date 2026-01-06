# Lab 02: IAM Security Best Practices

## Objective
Implement AWS IAM security controls aligned with CIS Benchmarks and GRC requirements.

## Learning Outcomes
- Configure IAM policies using least privilege principles
- Implement MFA for privileged accounts
- Set up IAM Access Analyzer for policy validation
- Create audit-ready IAM documentation

## Prerequisites
- AWS account with admin access
- AWS CLI configured
- Basic understanding of JSON policy syntax

## Lab Exercises

### Exercise 1: IAM Policy Analysis

Review and improve this overly permissive policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
```

**Improved version (least privilege for S3 read):**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:ListBucket"
    ],
    "Resource": [
      "arn:aws:s3:::my-bucket",
      "arn:aws:s3:::my-bucket/*"
    ]
  }]
}
```

### Exercise 2: MFA Enforcement

Create a policy that denies actions without MFA:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "BoolIfExists": {
        "aws:MultiFactorAuthPresent": "false"
      }
    }
  }]
}
```

### Exercise 3: IAM Access Analyzer

```bash
# Enable IAM Access Analyzer
aws accessanalyzer create-analyzer \
  --analyzer-name security-analyzer \
  --type ACCOUNT

# List findings
aws accessanalyzer list-findings \
  --analyzer-arn <analyzer-arn>
```

### Exercise 4: Credential Report

```bash
# Generate credential report
aws iam generate-credential-report

# Download and review
aws iam get-credential-report --query 'Content' --output text | base64 -d
```

## Compliance Mapping
| CIS Control | Implementation |
|-------------|----------------|
| 1.1 - No root access keys | Check credential report |
| 1.4 - Root MFA enabled | Verify in console |
| 1.5 - Password policy | `aws iam get-account-password-policy` |
| 1.16 - No full admin policies | IAM Access Analyzer |

## Deliverables
- [ ] Screenshot of IAM Access Analyzer with no critical findings
- [ ] Credential report showing MFA enabled for all users
- [ ] Custom least-privilege policy for your use case
