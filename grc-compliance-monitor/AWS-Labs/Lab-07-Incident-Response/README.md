# Lab 07: Incident Response

## Objective
Develop and test AWS incident response procedures aligned with NIST IR framework.

## Learning Outcomes
- Create incident response playbooks
- Implement automated containment
- Perform forensic data collection
- Document lessons learned

## NIST Incident Response Phases

1. **Preparation** - Tools, training, playbooks
2. **Detection & Analysis** - Identify and triage
3. **Containment, Eradication, Recovery** - Stop and fix
4. **Post-Incident Activity** - Lessons learned

## Lab Exercises

### Exercise 1: IR Playbook - Compromised EC2

```markdown
## Playbook: EC2 Instance Compromise

### Detection Triggers
- GuardDuty finding: UnauthorizedAccess:EC2/*
- High CPU/network from cryptomining
- Unusual outbound connections

### Containment Steps
1. [ ] Isolate instance (change security group)
2. [ ] Disable IAM role credentials
3. [ ] Capture memory dump (if applicable)
4. [ ] Create EBS snapshot for forensics

### Evidence Collection
1. [ ] CloudTrail logs for instance
2. [ ] VPC Flow Logs
3. [ ] System logs from instance
4. [ ] EBS snapshot

### Eradication
1. [ ] Terminate compromised instance
2. [ ] Rotate affected credentials
3. [ ] Update security groups/NACLs
4. [ ] Patch or replace vulnerable AMI

### Recovery
1. [ ] Deploy clean instance from hardened AMI
2. [ ] Restore data from clean backup
3. [ ] Verify security controls
4. [ ] Resume monitoring
```

### Exercise 2: Automated Containment

```python
# Lambda for automated EC2 isolation
import boto3

def isolate_instance(instance_id, vpc_id):
    ec2 = boto3.client('ec2')
    
    # Create quarantine security group
    quarantine_sg = ec2.create_security_group(
        GroupName=f'quarantine-{instance_id}',
        Description='Incident isolation - no traffic allowed',
        VpcId=vpc_id
    )
    
    # Apply to instance (replaces all SGs)
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[quarantine_sg['GroupId']]
    )
    
    # Disable instance profile
    ec2.disassociate_iam_instance_profile(
        AssociationId=get_association_id(instance_id)
    )
    
    # Create snapshot for forensics
    volumes = ec2.describe_volumes(
        Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}]
    )
    for vol in volumes['Volumes']:
        ec2.create_snapshot(
            VolumeId=vol['VolumeId'],
            Description=f'IR-snapshot-{instance_id}'
        )
    
    return {'status': 'isolated', 'instance_id': instance_id}
```

### Exercise 3: Evidence Collection Script

```bash
#!/bin/bash
# AWS IR Evidence Collection

INSTANCE_ID=$1
BUCKET="ir-evidence-bucket"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PREFIX="incident-$TIMESTAMP"

# Collect CloudTrail logs
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=$INSTANCE_ID \
  --start-time $(date -d '7 days ago' --iso-8601) \
  > cloudtrail-$INSTANCE_ID.json

# Collect VPC Flow Logs
aws logs filter-log-events \
  --log-group-name VPCFlowLogs \
  --filter-pattern "$INSTANCE_ID" \
  > flowlogs-$INSTANCE_ID.json

# Upload to S3 with integrity hash
for file in *.json; do
  sha256sum $file > $file.sha256
  aws s3 cp $file s3://$BUCKET/$PREFIX/
  aws s3 cp $file.sha256 s3://$BUCKET/$PREFIX/
done
```

### Exercise 4: Post-Incident Report Template

```markdown
## Incident Report: [INCIDENT-ID]

### Executive Summary
- **Date Detected**: 
- **Date Contained**:
- **Severity**: Critical/High/Medium/Low
- **Impact**: 

### Timeline
| Time | Event |
|------|-------|
| | Initial detection |
| | Containment initiated |
| | Root cause identified |
| | Recovery complete |

### Root Cause Analysis
[Description of how the incident occurred]

### Affected Systems
- 

### Actions Taken
1. 
2. 
3. 

### Lessons Learned
- What worked well:
- What needs improvement:

### Recommendations
1. 
2. 
```

## IR Automation Architecture

```
GuardDuty Finding → EventBridge → Step Functions
                                      ├── Isolate Instance (Lambda)
                                      ├── Collect Evidence (Lambda)
                                      ├── Notify Team (SNS)
                                      └── Create Ticket (Lambda → Jira)
```
