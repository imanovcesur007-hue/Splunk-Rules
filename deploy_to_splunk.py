import os
import json
import requests
import urllib3
import urllib.parse 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SPLUNK KONFİQURASİYASI (YENİ SERVER) ---
SPLUNK_HOST = "https://9.223.115.161:8089" 
SPLUNK_TOKEN = "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJtaWxsaXNlYyBmcm9tIHNwbHVua3NlcnZlciIsInN1YiI6Im1pbGxpc2VjIiwiYXVkIjoiR2l0aHViX2FwaSIsImlkcCI6IlNwbHVuayIsImp0aSI6Ijc2ZTkzZWM4M2Q3MGVhOGE1ZTU0MTRmOWI4YTQ1OWIwMTEwM2U4MGJkN2RlNGRjNmNiZmVlNmM4MjgxN2Q1NzkiLCJpYXQiOjE3ODIyMTc1NzAsImV4cCI6MTc4NDgwOTU3MCwibmJyIjoxNzgyMjE3NTcwfQ.fqp4Kcv9nuy_XSl0IyS6QcklHvgf17fOhPT4uOYp2P3cqPYo6VXRi_aobA3u15nUZs6KIMg517T0s-5yKN-wPw"
APP_CONTEXT = "search" 
API_ENDPOINT = f"{SPLUNK_HOST}/servicesNS/nobody/{APP_CONTEXT}/saved/searches"

# --- TELEGRAM KONFİQURASİYASI ---
TELEGRAM_BOT_TOKEN = "8875580959:AAEOvW7ZPzygkQwxc2vfsJT-FZt3P5jwCDc"
TELEGRAM_CHAT_ID = "-1004353279755"

headers = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/x-www-form-urlencoded"
}

RULES_DIR = "rules/splunk/"

def deploy_rule_to_splunk(rule_data):
    rule_name = rule_data["rule_name"]
    
    telegram_message = f"🚨 SOC ALERT: YENİ TƏHDİD AŞKARLANDI! 🚨\n\nQayda: {rule_name}\nKateqoriya: {rule_data['owasp_category']}\nCiddiyyət: {rule_data['severity']}\n\nTəcili Splunk panelinə daxil olub analiz edin!"
    encoded_message = urllib.parse.quote(telegram_message)
    TELEGRAM_WEBHOOK_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage?chat_id={TELEGRAM_CHAT_ID}&text={encoded_message}"
    
    payload = {
        "search": rule_data["search_query"],
        "description": f"{rule_data['description']} | OWASP Category: {rule_data['owasp_category']} | Severity: {rule_data['severity']}",
        "disabled": "0",
        "is_scheduled": "1",
        "cron_schedule": "* * * * *", 
        "dispatch.earliest_time": "0",
        "dispatch.latest_time": "now",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "actions": "webhook",
        "action.webhook": "1",
        "action.webhook.param.url": TELEGRAM_WEBHOOK_URL
    }

    print(f"Emal edilir: {rule_data['rule_id']} - {rule_name}...")
    
    create_payload = payload.copy()
    create_payload["name"] = rule_name
    
    response = requests.post(API_ENDPOINT, headers=headers, data=create_payload, verify=False)

    if response.status_code == 201:
        print(f"✅ YARADILDI: '{rule_name}' (Telegram Alert ilə).\n")
    elif response.status_code == 409:
        encoded_rule_name = urllib.parse.quote(rule_name)
        update_endpoint = f"{API_ENDPOINT}/{encoded_rule_name}"
        update_response = requests.post(update_endpoint, headers=headers, data=payload, verify=False)
        if update_response.status_code == 200:
             print(f"🔄 GÜNCƏLLƏNDİ: '{rule_name}' uğurla yeniləndi.\n")
        else:
             print(f"❌ XƏTA (Update): {update_response.status_code} - {update_response.text}\n")
    else:
        print(f"❌ XƏTA (Create): {response.status_code} - {response.text}\n")

def main():
    if not os.path.exists(RULES_DIR):
        print(f"❌ Qovluq tapılmadı: {RULES_DIR}")
        return
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".json"):
            filepath = os.path.join(RULES_DIR, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                try:
                    rule_data = json.load(f)
                    deploy_rule_to_splunk(rule_data)
                except json.JSONDecodeError:
                    print(f"❌ XƏTA: {filename} faylı düzgün JSON deyil.")

if __name__ == "__main__":
    main()
