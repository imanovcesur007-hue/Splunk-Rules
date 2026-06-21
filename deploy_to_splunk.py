import os
import json
import requests
import urllib3
import urllib.parse # Qayda adlarındakı boşluqları URL formatına salmaq üçün

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SPLUNK KONFİQURASİYASI ---
SPLUNK_HOST = "https://104.197.65.227:8089" 
SPLUNK_TOKEN = "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJtaWxsaXNlYyBmcm9tIHNwbHVua21haW5zZXJ2ZXIiLCJzdWIiOiJtaWxsaXNlYyIsImF1ZCI6IkdpdEh1YiBBUEkgU2tyaXB0aSIsImlkcCI6IlNwbHVuayIsImp0aSI6IjNkMzg4MTQ4OWEyNGY4NWM0MzIxNTUzNmVjODdkMDFhNTRmNzIyMTkwM2I4NjJmNjFjYjdiN2ZhMTgzYzdiMzQiLCJpYXQiOjE3ODE4ODcyODIsImV4cCI6MTc4NDQ3OTI4MiwibmJyIjoxNzgxODg3MjgyfQ.Yof2XsuxIWXLAPqJlW4XJ2FAYucNfRux-OzGqLei3BXcLb8LTpUnE5pAu5Kq5Ech5E7__phR7xp7TQD3M9O1aQ"
APP_CONTEXT = "search" 
API_ENDPOINT = f"{SPLUNK_HOST}/servicesNS/nobody/{APP_CONTEXT}/saved/searches"

headers = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/x-www-form-urlencoded"
}

RULES_DIR = "rules/splunk/"

def deploy_rule_to_splunk(rule_data):
    rule_name = rule_data["rule_name"]
    
    # Payload (ad hissəsini create üçün ayrıca verəcəyik)
    payload = {
        "search": rule_data["search_query"],
        "description": f"{rule_data['description']} | OWASP Category: {rule_data['owasp_category']} | Severity: {rule_data['severity']}",
        "disabled": "0",
        "is_scheduled": "1",
        "cron_schedule": "*/15 * * * *",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "action.webhook.param.owasp_category": rule_data["owasp_category"] 
    }

    print(f"Emal edilir: {rule_data['rule_id']} - {rule_name}...")
    
    # Əvvəlcə yaratmağa (Create) cəhd edirik
    create_payload = payload.copy()
    create_payload["name"] = rule_name
    
    response = requests.post(API_ENDPOINT, headers=headers, data=create_payload, verify=False)

    if response.status_code == 201:
        print(f"✅ YARADILDI: '{rule_name}' Splunk-a əlavə edildi.\n")
    elif response.status_code == 409:
        # Əgər 409 xətası alırıqsa, deməli qayda var. İndi UPDATE edirik!
        print(f"⚠️ Qayda mövcuddur. Güncəlləmə (Update) prosesi başladılır...")
        
        # Splunk API update üçün qayda adını URL-in sonunda tələb edir
        encoded_rule_name = urllib.parse.quote(rule_name)
        update_endpoint = f"{API_ENDPOINT}/{encoded_rule_name}"
        
        update_response = requests.post(update_endpoint, headers=headers, data=payload, verify=False)
        
        if update_response.status_code == 200:
             print(f"🔄 GÜNCƏLLƏNDİ: '{rule_name}' uğurla yeniləndi (index=main və s.).\n")
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
