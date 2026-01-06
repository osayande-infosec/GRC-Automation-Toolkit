# Lab 04: Workload Hardening

## Objective
Harden EC2 instances, containers, and serverless workloads following CIS Benchmarks and AWS best practices.

## Learning Outcomes
- Apply CIS Benchmark hardening to EC2
- Configure secure container deployments
- Implement Lambda security controls
- Automate compliance validation

## Lab Exercises

### Exercise 1: EC2 Hardening with SSM

```bash
# Install and configure SSM Agent for patch management
# User data script for Amazon Linux 2
#!/bin/bash
yum update -y
yum install -y amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Disable root login
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Enable auditd
yum install -y audit
systemctl enable auditd
systemctl start auditd
```

### Exercise 2: Security Groups (Least Privilege)

```bash
# Create restrictive security group
aws ec2 create-security-group \
  --group-name web-server-sg \
  --description "Web server security group"

# Allow only HTTPS
aws ec2 authorize-security-group-ingress \
  --group-name web-server-sg \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0

# Allow SSH only from bastion
aws ec2 authorize-security-group-ingress \
  --group-name web-server-sg \
  --protocol tcp \
  --port 22 \
  --source-group bastion-sg
```

### Exercise 3: Container Security (ECS/EKS)

```yaml
# ECS Task Definition with security settings
{
  "containerDefinitions": [{
    "name": "app",
    "image": "app:latest",
    "readonlyRootFilesystem": true,
    "user": "1000:1000",
    "privileged": false,
    "linuxParameters": {
      "capabilities": {
        "drop": ["ALL"]
      }
    }
  }]
}
```

### Exercise 4: Lambda Security

```python
# Secure Lambda function configuration
import boto3
import os

def handler(event, context):
    # Use environment variables for config (from Secrets Manager)
    # Never hardcode secrets
    
    # Validate input
    if not validate_input(event):
        raise ValueError("Invalid input")
    
    # Use VPC for sensitive operations
    # Configure in SAM/CloudFormation
    pass
```

```yaml
# SAM template with security settings
Resources:
  SecureFunction:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: python3.11
      Handler: app.handler
      VpcConfig:
        SecurityGroupIds: [!Ref LambdaSG]
        SubnetIds: [!Ref PrivateSubnet]
      ReservedConcurrentExecutions: 100  # DoS protection
      Environment:
        Variables:
          LOG_LEVEL: INFO
```

## CIS Benchmark Validation

```bash
# Run CIS-CAT scanner (requires license)
# Or use AWS Inspector for automated assessment
aws inspector2 create-filter \
  --name "CIS-EC2" \
  --filter-criteria '{"resourceType":[{"comparison":"EQUALS","value":"AWS_EC2_INSTANCE"}]}'
```

## Compliance Checklist
- [ ] IMDSv2 enforced (no IMDSv1)
- [ ] EBS volumes encrypted
- [ ] Security groups follow least privilege
- [ ] SSM Session Manager used instead of SSH
- [ ] Container images scanned before deployment
