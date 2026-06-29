# MilliBlueSec SIEM Detection Engineering

## Overview
This repository contains production-grade Splunk detection rules designed specifically for the `https://millibluesec.online/` infrastructure. The rule set strictly focuses on the OWASP Top 10 (2025) framework, ensuring robust security monitoring against critical web application vulnerabilities.

All rules are integrated into a DevSecOps CI/CD pipeline using GitHub Actions, enabling automated, idempotent deployments directly to the Splunk Enterprise REST API.

## Architecture
- **SIEM:** Splunk Enterprise (Dedicated Server, Isolated from Web Server)
- **Target Environment:** `https://millibluesec.online/`
- **Splunk Management Port:** 8090
- **Splunk API Endpoint:** `https://9.223.115.161:8089`
- **Log Sources:** Web Server Logs, Docker Logs, Container Logs
- **Alerting Integration:** Telegram API (Instant Notification)
- **Detection Window:** Real-time (Last 1 minute)

## Repository Structure
- `.github/workflows/deploy.yml`: CI/CD pipeline configuration for automated deployment.
- `rules/splunk/`: Directory containing JSON-formatted detection rules (SPL-OWASP-A01 to SPL-OWASP-A10).
- `deploy_to_splunk.py`: Core Python deployment script handling authentication, creation, updating, and deletion of Splunk Saved Searches.
- `requirements.txt`: Python dependencies required for the deployment environment.

## Detection Standards
Every rule in this repository adheres to strict Senior SOC Architect standards:
- **Precision:** Optimized SPL queries to minimize False Positives and ensure accurate detection in real production logs.
- **Context:** Enriched with MITRE ATT&CK mapping (Tactics & Techniques).
- **Actionability:** Includes dynamic severity, risk scoring, detailed descriptions, and mitigation recommendations.
- **Alerting:** Telegram alerts contain fully parsed, human-readable fields: Rule Name, Attack Type, Source IP, Destination URI, HTTP Method, Severity, Time, Host, Index, and Recommendation.

## Automation & CI/CD (GitHub Actions)
The deployment process is entirely automated and idempotent:
1. **Push/Merge:** Any modifications, additions, or deletions within `rules/splunk/*.json` automatically trigger the GitHub Actions workflow.
2. **Parse & Validate:** The `deploy_to_splunk.py` script validates the JSON rule schemas.
3. **Deploy:** The script communicates with the Splunk API using Bearer Token authentication to ensure the SIEM is perfectly synchronized with the repository state. Deleted rules in the repository are automatically removed from Splunk.

## Contact & Maintenance
Maintained by the Senior Security Engineering Team.
