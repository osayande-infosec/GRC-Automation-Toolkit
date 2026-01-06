## Python GRC Study Modules

Mini modules to practice automating common GRC tasks:
- Module 01: Password checker
- Module 02: Asset inventory
- Module 03: Log analyzer
- Module 04: Vulnerability reporter
- Module 05: Compliance dashboard
- Module 06: Risk assessment

### Setup
cd python-grc-study
python -m venv .venv
.venv\\Scripts\\activate    # on Windows
pip install -r requirements.txt

### Running the starter scripts
- Password strength check:
  python lesson-01-password-checker/password_checker.py --password  ExamplePass123!
- Batch password check (using sample list):
  python lesson-01-password-checker/password_checker_batch.py --file lesson-01-password-checker/passwords.sample.txt
- Asset inventory summary (CSV file path required):
  python lesson-02-asset-inventory/asset_inventory.py --csv inventory.csv
- Log analyzer (HTTP access-style logs):
  python lesson-03-log-analyzer/log_analyzer.py --log sample.log
- Vulnerability reporter (JSON file with findings):
  python lesson-04-vuln-reporter/vuln_reporter.py --json findings.json
- Compliance dashboard (JSON controls with status):
  python lesson-05-compliance-dashboard/compliance_dashboard.py --json controls.json
- Risk assessment (CSV risks with likelihood/impact):
  python lesson-06-risk-assessment/risk_assessment.py --csv risks.csv

Each script includes usage help (-h) and minimal inline docs. Extend these with real data and richer logic as you develop the labs.
