# Email Security Project

Email security controls and best practices for enterprise environments.

## Overview

This project covers implementation of email security controls including:
- SPF (Sender Policy Framework)
- DKIM (DomainKeys Identified Mail)  
- DMARC (Domain-based Message Authentication)
- Email gateway security
- Phishing prevention strategies

## Contents

- `interview-prep/` - Interview preparation materials for email security roles
- `showcase-project/` - Demonstration projects and implementations

## Email Authentication Flow

```
Sender → SPF Check → DKIM Verification → DMARC Policy → Recipient
           ↓              ↓                  ↓
        Pass/Fail     Pass/Fail         Quarantine/Reject/None
```

## Key Concepts

### SPF Record Example
```
v=spf1 include:_spf.google.com include:sendgrid.net -all
```

### DKIM Setup
1. Generate public/private key pair
2. Publish public key in DNS TXT record
3. Configure mail server to sign outbound emails

### DMARC Policy
```
v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; pct=100
```

## Resources

- [DMARC.org](https://dmarc.org/)
- [Google Postmaster Tools](https://postmaster.google.com/)
- [MXToolbox](https://mxtoolbox.com/)
