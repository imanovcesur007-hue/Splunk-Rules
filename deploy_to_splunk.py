import os
import json
import requests
import urllib3

# SSL xəbərdarlıqlarını gizlətmək üçün (test mühitləri üçün)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SPLUNK KONFİQURASİYASI ---
SPLUNK_HOST = "https://104.197.65.227:8089" 
SPLUNK_TOKEN = "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJ1bHZ1MTM0MiBmcm9tIGlwLTE3Mi0zMS00Ny0yNDEiLCJzdWIiOiJ1bHZ1MTM0MiIsImF1ZCI6InNlYXJjaCIsImlkcCI6IlNwbHVuayIsImp0aSI6IjAyMGIxZjZlNTAyODMyM2M1ZGY3ODYwMWJkZjc1M2I0MDJkYWQwNzI1NmRmMTczNTBmYTM3N2UzOWQxMWZjYjUiLCJpYXQiOjE3ODE5NjMzNzEsImV4cCI6MTg2ODM2MzM3MSwibmJyIjoxNzgxOTg1NTQyfQ.XqK58mhcee0Cf3rkirhw-hp60Wmi2-7rMcd9L6HUzGbUB8GL9hlVbX-aa53ANCvvaL4_SSv0nQxoY2mm9dkm2w"
APP_CONTEXT = "search" 
API_ENDPOINT = f"{SPLUNK_HOST}/servicesNS/nobody/{APP_CONTEXT}/saved/searches"

# Headers
headers = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/x-www-form-urlencoded"
}

# --- JSON FAYLLARININ YERLƏŞDİYİ QOVLUQ ---
RULES_DIR = "rules/splunk/"

def deploy_rule_to_splunk(rule_data):
    # JSON-dan gələn məlumatların Splunk API formatına uyğunlaşdırılması
    payload = {
        "name": rule_data["rule_name"],
        "search": rule_data["search_query"],
        "description": f"{rule_data['description']} | OWASP Category: {rule_data['owasp_category']} | Severity: {rule_data['severity']}",
        "disabled": "0", # 0 = Aktiv
        "is_scheduled": "1",
        "cron_schedule": "*/15 * * * *", # Hər 15 dəqiqədən bir yoxlayacaq
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "action.webhook.param.owasp_category": rule_data["owasp_category"] 
    }

    print(f"Göndərilir: {rule_data['rule_id']} - {rule_data['rule_name']}...")
    
    response = requests.post(
        API_ENDPOINT,
        headers=headers,
        data=payload,
        verify=False # Local/Test mühiti üçün SSL yoxlanışını söndürürük
    )

    if response.status_code == 201:
        print(f"✅ UĞURLU: '{rule_data['rule_name']}' Splunk-da yaradıldı.\n")
    elif response.status_code == 409:
         print(f"⚠️ DİQQƏT: '{rule_data['rule_name']}' artıq Splunk-da mövcuddur.\n")
    else:
        print(f"❌ XƏTA: Qayda yaradıla bilmədi. Status: {response.status_code}")
        print(f"Xəta mesajı: {response.text}\n")

def main():
    # Qovluğun mövcudluğunu yoxlayırıq
    if not os.path.exists(RULES_DIR):
        print(f"❌ Qovluq tapılmadı: {RULES_DIR}\nZəhmət olmasa skripti repozitoriyanın əsas qovluğunda işə salın.")
        return

    # JSON fayllarını tapıb tək-tək Splunk-a göndəririk
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".json"):
            filepath = os.path.join(RULES_DIR, filename)
            
            with open(filepath, 'r', encoding='utf-8') as f:
                try:
                    rule_data = json.load(f)
                    deploy_rule_to_splunk(rule_data)
                except json.JSONDecodeError:
                    print(f"❌ XƏTA: {filename} faylı düzgün JSON formatında deyil.")

if __name__ == "__main__":
    main()
