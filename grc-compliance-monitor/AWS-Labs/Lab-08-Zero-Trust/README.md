# Lab 08: Zero Trust Architecture

## Objective
Implement Zero Trust principles in AWS following the "never trust, always verify" paradigm.

## Learning Outcomes
- Implement identity-centric access controls
- Configure network micro-segmentation
- Enable continuous verification
- Apply least privilege at all layers

## Zero Trust Principles

1. **Verify Explicitly** - Always authenticate and authorize
2. **Least Privilege Access** - Just-in-time, just-enough access
3. **Assume Breach** - Minimize blast radius, segment access

## Lab Exercises

### Exercise 1: Identity-Centric Access (IAM)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::sensitive-data/*",
      "Condition": {
        "Bool": {"aws:MultiFactorAuthPresent": "true"},
        "IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]},
        "StringEquals": {"aws:PrincipalTag/Department": "Finance"}
      }
    }
  ]
}
```

### Exercise 2: Network Micro-Segmentation

```bash
# Create separate security groups per tier
# Web tier - only HTTPS from ALB
aws ec2 create-security-group --group-name web-tier --vpc-id vpc-xxx
aws ec2 authorize-security-group-ingress \
  --group-name web-tier \
  --protocol tcp --port 443 \
  --source-group alb-sg

# App tier - only from web tier on specific port
aws ec2 create-security-group --group-name app-tier --vpc-id vpc-xxx
aws ec2 authorize-security-group-ingress \
  --group-name app-tier \
  --protocol tcp --port 8080 \
  --source-group web-tier

# DB tier - only from app tier
aws ec2 create-security-group --group-name db-tier --vpc-id vpc-xxx
aws ec2 authorize-security-group-ingress \
  --group-name db-tier \
  --protocol tcp --port 5432 \
  --source-group app-tier
```

### Exercise 3: AWS Verified Access

```yaml
# Verified Access for application access without VPN
Resources:
  VerifiedAccessEndpoint:
    Type: AWS::EC2::VerifiedAccessEndpoint
    Properties:
      ApplicationDomain: app.internal.example.com
      AttachmentType: vpc
      DomainCertificateArn: !Ref Certificate
      EndpointType: load-balancer
      LoadBalancerOptions:
        LoadBalancerArn: !Ref ALB
        Port: 443
        Protocol: https
      PolicyDocument: |
        permit(principal, action, resource)
        when {
          context.identity.groups.contains("developers") &&
          context.identity.mfa == true
        };
      VerifiedAccessGroupId: !Ref VerifiedAccessGroup
```

### Exercise 4: Service-to-Service Auth

```python
# Use IAM roles for service authentication
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

def call_internal_api(url, data):
    session = boto3.Session()
    credentials = session.get_credentials()
    
    request = AWSRequest(method='POST', url=url, data=data)
    SigV4Auth(credentials, 'execute-api', 'us-east-1').add_auth(request)
    
    # Now the request has IAM signature for verification
    return requests.post(url, headers=dict(request.headers), data=data)
```

### Exercise 5: Continuous Verification

```yaml
# Config Rules for continuous compliance
Resources:
  MFAEnabledRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: iam-user-mfa-enabled
      Source:
        Owner: AWS
        SourceIdentifier: IAM_USER_MFA_ENABLED
      
  EncryptedVolumesRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: encrypted-volumes
      Source:
        Owner: AWS
        SourceIdentifier: ENCRYPTED_VOLUMES

  RestrictedSSHRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: restricted-ssh
      Source:
        Owner: AWS
        SourceIdentifier: INCOMING_SSH_DISABLED
```

## Zero Trust Architecture Diagram

```
                    ┌─────────────────┐
                    │  Identity (IAM) │
                    │  + MFA + Tags   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Verified Access │
                    │  or VPN + Auth  │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
   ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
   │ Web SG  │ ──────► │ App SG  │ ──────► │  DB SG  │
   │(443 only)│         │(8080)   │         │(5432)   │
   └─────────┘         └─────────┘         └─────────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  CloudTrail +   │
                    │  GuardDuty      │
                    │  (Monitoring)   │
                    └─────────────────┘
```

## Zero Trust Checklist
- [ ] All users require MFA
- [ ] IAM policies use conditions (IP, time, tags)
- [ ] Network segmented by function
- [ ] Service-to-service uses IAM auth
- [ ] All traffic logged and monitored
- [ ] Secrets rotated automatically
- [ ] Config rules enforce compliance
