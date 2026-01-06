# GRC Compliance Platform

A **Vanta-style** compliance automation platform built with FastAPI, providing continuous security monitoring, automated evidence collection, and multi-framework compliance tracking.

## 🎯 Overview

This platform evolves the CLI-based GRC Automation Tools into a full-featured compliance SaaS solution, enabling organizations to:

- **Automate Compliance**: Continuous monitoring against SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST CSF
- **Centralize Evidence**: Single source of truth for audit evidence and documentation
- **Track Risks**: Enterprise risk register with 5x5 matrix visualization
- **Manage Vulnerabilities**: CVSS-based prioritization with SLA tracking
- **Monitor Assets**: Complete IT asset inventory with lifecycle management
- **Integrate Tools**: Connect with AWS, Azure, Okta, GitHub, and more

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Frontend (Future)                         │
│                    React / Next.js Dashboard                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │Compliance│ │  Asset   │ │   Risk   │ │  Vuln    │           │
│  │ Tracking │ │Management│ │ Register │ │ Scanner  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │Credential│ │   Log    │ │Dashboard │ │Integration│          │
│  │  Audit   │ │ Analysis │ │  API     │ │  Engine  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │PostgreSQL│  │  Redis   │  │  Celery  │
        │    DB    │  │  Cache   │  │ Workers  │
        └──────────┘  └──────────┘  └──────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)
- PostgreSQL 16+ (or use Docker)

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/osayande-infosec/GRC-Automation-Toolkit.git
cd GRC-Automation-Toolkit/compliance-platform

# Copy environment template
cp .env.example .env

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api
```

The API will be available at `http://localhost:8000`

### Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL=postgresql://user:pass@localhost:5432/compliance_db
export SECRET_KEY=your-secret-key-here

# Run migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload
```

## 📚 API Documentation

Once running, access interactive API docs at:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

### API Endpoints

| Module | Endpoint | Description |
|--------|----------|-------------|
| **Auth** | `POST /api/v1/auth/token` | Get JWT token |
| **Credentials** | `POST /api/v1/credentials/audit` | Audit password strength |
| **Assets** | `GET /api/v1/assets` | List all assets |
| **Vulnerabilities** | `GET /api/v1/vulnerabilities` | List vulnerabilities |
| **Compliance** | `GET /api/v1/compliance/frameworks` | Get framework status |
| **Risks** | `GET /api/v1/risks` | List risk register |
| **Logs** | `POST /api/v1/logs/analyze` | Analyze security logs |
| **Dashboard** | `GET /api/v1/dashboard/summary` | Executive summary |
| **Integrations** | `GET /api/v1/integrations` | List integrations |

## 🔐 Authentication

The platform uses JWT-based authentication with role-based access control (RBAC):

| Role | Permissions |
|------|-------------|
| `admin` | Full access - manage users, configure integrations |
| `analyst` | Read/write access - manage assets, risks, compliance |
| `viewer` | Read-only access - view dashboards and reports |

### Getting a Token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@example.com&password=yourpassword"
```

### Using the Token

```bash
curl -X GET "http://localhost:8000/api/v1/assets" \
  -H "Authorization: Bearer <your-token>"
```

## 🔌 Integrations

### Supported Platforms

| Platform | Integration Type | Status |
|----------|-----------------|--------|
| **AWS** | Asset discovery, CloudTrail logs | ✅ Ready |
| **Azure** | Resource inventory, Activity logs | ✅ Ready |
| **Okta** | User directory, SSO events | ✅ Ready |
| **GitHub** | Repository security, code scanning | ✅ Ready |
| **Qualys** | Vulnerability scanning | 🔄 Planned |
| **CrowdStrike** | EDR telemetry | 🔄 Planned |

### Configuring Integrations

```bash
# AWS Integration
curl -X POST "http://localhost:8000/api/v1/integrations" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AWS Production",
    "type": "aws",
    "config": {
      "access_key_id": "AKIA...",
      "secret_access_key": "...",
      "region": "us-east-1"
    }
  }'
```

## 📊 Compliance Frameworks

The platform supports continuous compliance monitoring for:

| Framework | Controls | Auto-Evidence |
|-----------|----------|---------------|
| **SOC 2 Type II** | 64 controls | ✅ |
| **ISO 27001:2022** | 93 controls | ✅ |
| **NIST CSF** | 108 subcategories | ✅ |
| **HIPAA** | 54 requirements | ✅ |
| **PCI-DSS 4.0** | 12 requirements | ✅ |
| **CIS Controls v8** | 153 safeguards | ✅ |

### Control Mappings

The platform maintains cross-framework mappings, so evidence collected for one framework automatically applies to related controls in other frameworks.

## 🗄️ Database Models

```
Organizations ──┬── Users
                ├── Assets
                ├── Controls ── Evidence
                ├── Risks
                ├── Vulnerabilities
                └── Integrations
                
AuditLog (tracks all changes)
```

## 🔄 Background Tasks (Celery)

Automated tasks running on schedule:

| Task | Schedule | Description |
|------|----------|-------------|
| `sync_aws_assets` | Every 6 hours | Discover AWS resources |
| `scan_vulnerabilities` | Daily | Run vulnerability scans |
| `collect_evidence` | Weekly | Gather compliance evidence |
| `generate_reports` | Monthly | Create compliance reports |
| `check_sla_breaches` | Hourly | Alert on SLA violations |

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test module
pytest tests/test_compliance.py -v
```

## 📈 Roadmap

### Phase 1: Foundation (Current)
- [x] FastAPI backend scaffold
- [x] Database models
- [x] Authentication & RBAC
- [x] Core API endpoints
- [ ] Database migrations
- [ ] Unit tests

### Phase 2: Integrations
- [ ] AWS asset discovery
- [ ] Azure resource sync
- [ ] Okta user directory
- [ ] GitHub security alerts

### Phase 3: Automation
- [ ] Automated evidence collection
- [ ] Compliance gap detection
- [ ] Risk scoring algorithms
- [ ] SLA monitoring

### Phase 4: Frontend
- [ ] React/Next.js dashboard
- [ ] Real-time notifications
- [ ] Executive reporting
- [ ] Audit preparation tools

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## 👨‍💻 Author

**Osayande** - CISSP Certified Security Professional

- GitHub: [@osayande-infosec](https://github.com/osayande-infosec)
- LinkedIn: [Connect for GRC discussions](https://linkedin.com)

---

*Building towards enterprise-grade compliance automation, one commit at a time.* 🛡️
