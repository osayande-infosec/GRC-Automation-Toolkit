# Lab 03: CI/CD Security

## Objective
Implement secure CI/CD pipelines using AWS CodePipeline, CodeBuild, and security scanning tools.

## Learning Outcomes
- Configure secure build environments
- Integrate security scanning into pipelines
- Implement secrets management
- Enforce infrastructure-as-code security

## Lab Exercises

### Exercise 1: Secure CodeBuild Project

```yaml
# buildspec.yml with security scanning
version: 0.2
phases:
  install:
    commands:
      - pip install bandit safety
  pre_build:
    commands:
      # SAST scanning
      - bandit -r src/ -f json -o bandit-report.json || true
      # Dependency scanning
      - safety check -r requirements.txt --json > safety-report.json || true
  build:
    commands:
      - python setup.py build
  post_build:
    commands:
      # Fail if critical issues found
      - python scripts/check-security-gates.py
artifacts:
  files:
    - '**/*'
  secondary-artifacts:
    security-reports:
      files:
        - bandit-report.json
        - safety-report.json
```

### Exercise 2: Secrets Management

```bash
# Store secrets in AWS Secrets Manager
aws secretsmanager create-secret \
  --name /app/prod/database \
  --secret-string '{"username":"admin","password":"secure-password"}'

# Reference in CodeBuild
# buildspec.yml
env:
  secrets-manager:
    DB_PASSWORD: /app/prod/database:password
```

### Exercise 3: Infrastructure as Code Security

```bash
# Install and run cfn-nag for CloudFormation scanning
gem install cfn-nag
cfn_nag_scan --input-path templates/

# Install and run tfsec for Terraform
brew install tfsec
tfsec ./terraform/
```

### Exercise 4: Pipeline Security Controls

```yaml
# CodePipeline with approval stage
Stages:
  - Name: Source
    Actions: [...]
  - Name: SecurityScan
    Actions:
      - Name: SAST
        ActionTypeId:
          Category: Build
          Provider: CodeBuild
  - Name: ManualApproval
    Actions:
      - Name: SecurityReview
        ActionTypeId:
          Category: Approval
          Provider: Manual
  - Name: Deploy
    Actions: [...]
```

## Security Gates Checklist
- [ ] No hardcoded secrets in code
- [ ] Dependencies free of critical CVEs
- [ ] SAST findings below threshold
- [ ] IaC templates pass security scan
- [ ] Container images scanned
