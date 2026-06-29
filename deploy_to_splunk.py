import os
import json
import glob
import requests
import urllib3

# SSL xəbərdarlıqlarını söndürmək üçün (Splunk self-signed sertifikat istifadə edirsə)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Mühit dəyişənlərindən məlumatları çəkirik
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://9.223.115.161:8089")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
RULES_DIR = "rules/splunk"

headers = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}"
}

def get_existing_searches():
    url = f"{SPLUNK_HOST}/services/saved/searches?output_mode=json"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return [entry['name'] for entry in response.json().get('entry', [])]
    return []

def deploy_rule(filepath, existing_searches):
    with open(filepath, 'r', encoding='utf-8') as file:
        rule_data = json.load(file)
    
    rule_name = rule_data["name"]
    payload = {
        "search": rule_data["search"],
        "cron_schedule": rule_data["cron_schedule"],
        "is_scheduled": "1",
        "description": rule_data["description"],
        "action.webhook": "1", # Webhook aktivləşdirilir
        "alert_type": "always",
        "alert.severity": rule_data["severity_level"]
    }

    if rule_name in existing_searches:
        # Update mövcud rule
        url = f"{SPLUNK_HOST}/services/saved/searches/{rule_name}"
        response = requests.post(url, headers=headers, data=payload, verify=False)
        print(f"[{response.status_code}] UPDATED: {rule_name}")
    else:
        # Create yeni rule
        payload["name"] = rule_name
        url = f"{SPLUNK_HOST}/services/saved/searches"
        response = requests.post(url, headers=headers, data=payload, verify=False)
        print(f"[{response.status_code}] CREATED: {rule_name}")

if __name__ == "__main__":
    if not SPLUNK_TOKEN:
        print("XƏTA: SPLUNK_TOKEN tapılmadı!")
        exit(1)
        
    existing_searches = get_existing_searches()
    rule_files = glob.glob(f"{RULES_DIR}/*.json")
    
    for file_path in rule_files:
        deploy_rule(file_path, existing_searches)
