## GRC Automation Toolkit (Showcase) 
 
Lightweight lab-style projects to demonstrate GRC automation. Each subfolder is self-contained. 
 
### Repository layout 
- email-security-project/ - email security controls 
- grc-compliance-monitor/ - AWS compliance/detection/IR labs 
- python-grc-study/ - Python modules for password, inventory, logs, vuln reporting, dashboards, risk scoring 
 
### Getting started 
1) Clone the repo and enter the folder: 
   git clone https://github.com/osayande-infosec/GRC-Automation-Toolkit.git 
   cd GRC-Automation-Toolkit 
2) Optional: create a Python venv in python-grc-study 
   python -m venv .venv 
   .venv\Scripts\activate 
   pip install -r requirements.txt 
3) Open a lab directory and follow its steps. 
 
### Quickstart for Python labs 
cd python-grc-study 
python -m venv .venv 
.venv\Scripts\activate    # on Windows 
pip install -r requirements.txt 
python lesson-01-password-checker/password_checker.py --password ExamplePass123! 
 
### Roadmap / next refinements 
- Add per-lab READMEs with objectives and success criteria. 
- Expand Python modules into notebooks with sample datasets. 
- Add AWS detections/playbooks in grc-compliance-monitor. 
- Grow CI to include linting/tests as code matures.
