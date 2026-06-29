import os
import json
import requests
import urllib3
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- KONFİQURASİYA ---
SPLUNK_HOST     = "https://9.223.115.161:8089  1111"
SPLUNK_TOKEN    = "1111 eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJtaWxsaXNlYyBmcm9tIHNwbHVua3NlcnZlciIsInN1YiI6Im1pbGxpc2VjIiwiYXVkIjoiR2l0aHViX2FwaSIsImlkcCI6IlNwbHVuayIsImp0aSI6Ijc2ZTkzZWM4M2Q3MGVhOGE1ZTU0MTRmOWI4YTQ1OWIwMTEwM2U4MGJkN2RlNGRjNmNiZmVlNmM4MjgxN2Q1NzkiLCJpYXQiOjE3ODIyMTc1NzAsImV4cCI6MTc4NDgwOTU3MCwibmJyIjoxNzgyMjE3NTcwfQ.fqp4Kcv9nuy_XSl0IyS6QcklHvgf17fOhPT4uOYp2P3cqPYo6VXRi_aobA3u15nUZs6KIMg517T0s-5yKN-wPw"
TELEGRAM_TOKEN  = "8875580959:AAEOvW7ZPzygkQwxc2vfsJT-FZt3P5jwCDc   111"
TELEGRAM_CHAT   = "-1004353279755  111"
APP_CONTEXT     = "search"
RULES_DIR       = "rules/splunk/"

API_ENDPOINT = f"{SPLUNK_HOST}/servicesNS/nobody/{APP_CONTEXT}/saved/searches"
HEADERS = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/x-www-form-urlencoded"
}


def build_telegram_url(rule):
    msg = (
        f"🚨 SOC ALERT: YENİ TƏHDİD AŞKARLANDI! 🚨\n\n"
        f"Qayda: {rule['rule_name']}\n"
        f"OWASP: {rule['owasp_id']}\n"
        f"Ciddiyyət: {rule['severity']}\n\n"
        f"Təcili Splunk panelinə daxil olub analiz edin!"
    )
    return (
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        f"?chat_id={TELEGRAM_CHAT}&text={urllib.parse.quote(msg)}"
    )


def deploy(rule):
    name = rule["rule_name"]
    print(f"Emal edilir: {rule.get('rule_id', '?')} - {name}...")

    payload = {
        "search":                   rule["search_query"],
        "description":              f"OWASP {rule['owasp_id']} | Severity: {rule['severity']}",
        "disabled":                 "0",
        "is_scheduled":             "1",
        "cron_schedule":            "* * * * *",
        "dispatch.earliest_time":   "0",
        "dispatch.latest_time":     "now",
        "alert_type":               "number of events",
        "alert_comparator":         "greater than",
        "alert_threshold":          "0",
        "actions":                  "webhook",
        "action.webhook":           "1",
        "action.webhook.param.url": build_telegram_url(rule)
    }

    # Yarat
    resp = requests.post(API_ENDPOINT, headers=HEADERS,
                         data={**payload, "name": name}, verify=False)

    if resp.status_code == 201:
        print(f"✅ YARADILDI: '{name}'\n")

    elif resp.status_code == 409:
        # Mövcuddur — yenilə
        url = f"{API_ENDPOINT}/{urllib.parse.quote(name)}"
        resp2 = requests.post(url, headers=HEADERS, data=payload, verify=False)
        if resp2.status_code == 200:
            print(f"🔄 GÜNCƏLLƏNDİ: '{name}'\n")
        else:
            print(f"❌ XƏTA (update): {resp2.status_code} - {resp2.text}\n")

    else:
        print(f"❌ XƏTA (create): {resp.status_code} - {resp.text}\n")


def main():
    if not os.path.exists(RULES_DIR):
        print(f"❌ Qovluq tapılmadı: {RULES_DIR}")
        return

    for fname in sorted(os.listdir(RULES_DIR)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(RULES_DIR, fname)
        with open(path, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"❌ Düzgün JSON deyil: {fname}")
                continue

        # Array və ya tək object dəstəyi
        rules = data if isinstance(data, list) else [data]
        for rule in rules:
            deploy(rule)


if __name__ == "__main__":
    main()
