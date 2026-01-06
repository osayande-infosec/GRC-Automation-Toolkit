# Lab 05: Security Monitoring

## Objective
Implement comprehensive security monitoring using AWS native services for GRC compliance.

## Learning Outcomes
- Configure CloudTrail for audit logging
- Set up CloudWatch alarms for security events
- Implement VPC Flow Logs analysis
- Create security dashboards

## Lab Exercises

### Exercise 1: CloudTrail Configuration

```bash
# Create CloudTrail with encryption and validation
aws cloudtrail create-trail \
  --name security-audit-trail \
  --s3-bucket-name audit-logs-bucket \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id alias/cloudtrail-key

# Enable logging
aws cloudtrail start-logging --name security-audit-trail

# Enable CloudTrail Insights
aws cloudtrail put-insight-selectors \
  --trail-name security-audit-trail \
  --insight-selectors '[{"InsightType":"ApiCallRateInsight"},{"InsightType":"ApiErrorRateInsight"}]'
```

### Exercise 2: CloudWatch Security Alarms

```bash
# Create metric filter for root login
aws logs put-metric-filter \
  --log-group-name CloudTrail/logs \
  --filter-name RootAccountUsage \
  --filter-pattern '{ $.userIdentity.type = "Root" }' \
  --metric-transformations \
    metricName=RootAccountUsageCount,metricNamespace=Security,metricValue=1

# Create alarm
aws cloudwatch put-metric-alarm \
  --alarm-name RootAccountUsage \
  --metric-name RootAccountUsageCount \
  --namespace Security \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:region:account:security-alerts
```

### Exercise 3: VPC Flow Logs

```bash
# Enable VPC Flow Logs to CloudWatch
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345678 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name VPCFlowLogs

# Query for rejected traffic
aws logs filter-log-events \
  --log-group-name VPCFlowLogs \
  --filter-pattern "REJECT"
```

### Exercise 4: Security Hub Dashboard

```bash
# Enable Security Hub
aws securityhub enable-security-hub \
  --enable-default-standards

# Enable specific standards
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0

# Get findings summary
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}'
```

### Exercise 5: CloudWatch Dashboard

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "title": "Security Events",
        "metrics": [
          ["Security", "RootAccountUsageCount"],
          ["Security", "UnauthorizedAPICalls"],
          ["Security", "IAMPolicyChanges"]
        ]
      }
    },
    {
      "type": "log",
      "properties": {
        "title": "Recent Security Events",
        "query": "fields @timestamp, @message | filter @message like /unauthorized/"
      }
    }
  ]
}
```

## Key Metrics to Monitor
| Metric | Threshold | Action |
|--------|-----------|--------|
| Root account usage | Any | Immediate alert |
| Failed login attempts | >5 in 5 min | Alert |
| Security group changes | Any | Review |
| IAM policy changes | Any | Review |
| S3 bucket policy changes | Any | Alert |
