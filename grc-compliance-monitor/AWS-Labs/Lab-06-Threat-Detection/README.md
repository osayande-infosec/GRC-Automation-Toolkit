# Lab 06: Threat Detection

## Objective
Implement AWS threat detection services for proactive security monitoring.

## Learning Outcomes
- Configure Amazon GuardDuty for threat detection
- Set up AWS Inspector for vulnerability assessment
- Implement Amazon Macie for data security
- Automate threat response

## Lab Exercises

### Exercise 1: GuardDuty Setup

```bash
# Enable GuardDuty
aws guardduty create-detector --enable

# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Enable S3 protection
aws guardduty update-detector \
  --detector-id $DETECTOR_ID \
  --data-sources S3Logs={Enable=true}

# Enable EKS protection
aws guardduty update-detector \
  --detector-id $DETECTOR_ID \
  --data-sources Kubernetes={AuditLogs={Enable=true}}

# List findings
aws guardduty list-findings --detector-id $DETECTOR_ID
```

### Exercise 2: GuardDuty Finding Types

Key threat categories to monitor:
- **UnauthorizedAccess**: Unusual API activity
- **Recon**: Port scanning, DNS probing  
- **Trojan**: Command and control activity
- **Cryptocurrency**: Mining detection
- **Exfiltration**: Data exfiltration attempts

### Exercise 3: AWS Inspector

```bash
# Enable Inspector v2
aws inspector2 enable \
  --resource-types EC2 ECR LAMBDA

# Create assessment
aws inspector2 list-findings \
  --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}'

# Get coverage
aws inspector2 list-coverage
```

### Exercise 4: Amazon Macie

```bash
# Enable Macie
aws macie2 enable-macie

# Create classification job for S3
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "PII-Discovery" \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "123456789012",
      "buckets": ["data-bucket"]
    }]
  }'

# List findings
aws macie2 list-findings
```

### Exercise 5: Automated Response

```python
# Lambda function for GuardDuty auto-remediation
import boto3

def handler(event, context):
    finding = event['detail']
    finding_type = finding['type']
    
    if 'UnauthorizedAccess:EC2/SSHBruteForce' in finding_type:
        # Block the attacking IP
        ec2 = boto3.client('ec2')
        instance_id = finding['resource']['instanceDetails']['instanceId']
        
        # Update NACL to block attacker
        # Or isolate instance to quarantine security group
        
    elif 'Exfiltration:S3/MaliciousIPCaller' in finding_type:
        # Restrict S3 bucket access
        s3 = boto3.client('s3')
        bucket = finding['resource']['s3BucketDetails']['name']
        # Add deny policy for malicious IP
```

## Threat Detection Matrix

| Service | Detects | Data Source |
|---------|---------|-------------|
| GuardDuty | Network threats, account compromise | VPC Flow Logs, DNS, CloudTrail |
| Inspector | Vulnerabilities, misconfigs | EC2, ECR, Lambda |
| Macie | Data exposure, PII | S3 |
| Security Hub | Aggregated findings | All services |

## Alert Priorities
- **Critical**: Active exploitation, data exfiltration
- **High**: Reconnaissance, unusual access patterns
- **Medium**: Misconfigurations, policy violations
- **Low**: Informational findings
