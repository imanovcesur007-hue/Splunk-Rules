import os
import json
import requests
import urllib3
from pathlib import Path

# SSL xəbərdarlıqlarını söndürmək üçün (Self-signed sertifikatlar üçün)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Mühit Dəyişənləri (GitHub Secrets-dən gələcək)
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://9.223.115.161:8089")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT = os.getenv("TELEGRAM_CHAT")

# Telegram URL (Splunk webhook-u bu linkə POST atacaq) - XƏTA DÜZƏLDİLDİ
TELEGRAM_WEBHOOK_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage?chat_id={TELEGRAM_CHAT}&text=Diqqet!+Yeni+Hucum+Detect+Olundu:+millibluesec.online"

def deploy_rules():
    headers = {
        "Authorization": f"Bearer {SPLUNK_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    rules_dir = Path("rules/splunk")
    for rule_file in rules_dir.glob("*.json"):
        with open(rule_file, "r", encoding="utf-8") as f:
            rule_data = json.load(f)
            
        rule_name = rule_data["name"]
        
        # Splunk REST API üçün payload
        payload = {
            "name": rule_name,
            "search": rule_data["search"],
            "cron_schedule": rule_data["cron_schedule"], # * * * * * (Hər dəqiqə)
            "is_scheduled": "1",
            "dispatch.earliest_time": "-1m", # Son 1 dəqiqə logları
            "dispatch.latest_time": "now",
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "description": rule_data["description"],
            "action.webhook": "1",
            "action.webhook.param.url": TELEGRAM_WEBHOOK_URL
        }

        print(f"Deploying rule: {rule_name}...")
        
        # Qaydanın mövcud olub-olmadığını yoxlayıb, yeniləyirik və ya yaradırıq
        url = f"{SPLUNK_HOST}/services/saved/searches"
        
        # Əvvəl yaratmağa cəhd edirik
        response = requests.post(url, headers=headers, data=payload, verify=False)
        
        if response.status_code == 201:
            print(f"[{rule_name}] Ugurla yaradildi!")
        elif response.status_code == 409: # 409 Conflict o deməkdir ki, qayda artıq var. Update edirik.
            print(f"[{rule_name}] Artiq movcuddu. Update edilir...")
            update_url = f"{url}/{rule_name}"
            update_response = requests.post(update_url, headers=headers, data=payload, verify=False)
            if update_response.status_code == 200:
                print(f"[{rule_name}] Ugurla update olundu!")
            else:
                print(f"Update zamani xeta [{rule_name}]: {update_response.text}")
        else:
            print(f"Xeta bas verdi [{rule_name}]: {response.status_code} - {response.text}")

if __name__ == "__main__":
    if not SPLUNK_TOKEN:
        print("XETA: SPLUNK_TOKEN teyin edilmeyib!")
        exit(1)
    deploy_rules()
