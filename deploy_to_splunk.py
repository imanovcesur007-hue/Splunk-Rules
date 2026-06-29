import os
import glob
import requests
import logging
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://9.223.115.161:8089")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJtaWxsaXNlYyBmcm9tIHNwbHVua3NlcnZlciIsInN1YiI6Im1pbGxpc2VjIiwiYXVkIjoiR2l0aHViX2FwaSIsImlkcCI6IlNwbHVuayIsImp0aSI6Ijc2ZTkzZWM4M2Q3MGVhOGE1ZTU0MTRmOWI4YTQ1OWIwMTEwM2U4MGJkN2RlNGRjNmNiZmVlNmM4MjgxN2Q1NzkiLCJpYXQiOjE3ODIyMTc1NzAsImV4cCI6MTc4NDgwOTU3MCwibmJyIjoxNzgyMjE3NTcwfQ.fqp4Kcv9nuy_XSl0IyS6QcklHvgf17fOhPT4uOYp2P3cqPYo6VXRi_aobA3u15nUZs6KIMg517T0s-5yKN-wPw")
APP_CONTEXT = "search"
OWNER = "nobody"

TELEGRAM_TOKEN = "8875580959:AAEOvW7ZPzygkQwxc2vfsJT-FZt3P5jwCDc"
TELEGRAM_CHAT_ID = "-1004353279755"

# YENİLƏNMİŞ TELEGRAM WEBHOOK (Bizim sadə .conf fayllarımızla 100% uyğun işləməsi üçün)
WEBHOOK_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage?chat_id={TELEGRAM_CHAT_ID}&parse_mode=HTML&text=%F0%9F%9A%A8%20%3Cb%3EMilliBlueSec%20SIEM%20Alert%3C%2Fb%3E%20%F0%9F%9A%A8%0A%0A%3Cb%3EQayda%3A%3C%2Fb%3E%20%24name%24%0A%3Cb%3EH%C3%BCcum%20Vaxt%C4%B1%3A%3C%2Fb%3E%20%24result._time%24%0A%0A%E2%9A%A0%EF%B8%8F%20%3Cb%3ET%C9%99cili%20Splunk%20panelin%C9%99%20daxil%20olub%20loglar%C4%B1%20analiz%20edin%21%3C%2Fb%3E"

if not SPLUNK_TOKEN:
    logger.error("CRITICAL: SPLUNK_TOKEN tapılmadı! Deployment dayandırılır.")
    sys.exit(1)

HEADERS = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
API_BASE_URL = f"{SPLUNK_HOST}/servicesNS/{OWNER}/{APP_CONTEXT}/saved/searches"


def get_existing_rules():
    # YENİLƏNİB: Artıq fayl adlarına uyğun olaraq "_Detection" sözü ilə bitən qaydaları axtarır
    params = {"output_mode": "json", "count": 0, "search": "name=*_Detection"}
    try:
        res = requests.get(API_BASE_URL, headers=HEADERS, params=params, verify=False, timeout=30)
        res.raise_for_status()
        return {entry["name"]: entry for entry in res.json().get("entry", [])}
    except requests.exceptions.RequestException as e:
        logger.error(f"Splunk API xətası: {e}")
        sys.exit(1)


def read_local_rules():
    local_rules = {}
    base_path = os.path.dirname(os.path.abspath(__file__))
    
    # YENİLƏNİB: Fayl yolu GitHub repozitoriyanızın şəklinə uyğunlaşdırıldı
    search_path = os.path.join(base_path, "rules", "*.conf")
    
    logger.info(f"Axtarış yolu: {search_path}")
    files = glob.glob(search_path)
    logger.info(f"Tapılan fayllar: {files}")
    
    if not files:
        logger.warning("Heç bir fayl tapılmadı!")
        return local_rules
    
    for file_path in files:
        rule_name = os.path.basename(file_path).replace(".conf", "")
        with open(file_path, "r", encoding="utf-8") as f:
            spl_query = f.read().strip()
        
        if not spl_query:
            continue

        payload = {
            "name": rule_name,
            "search": spl_query,
            "cron_schedule": "* * * * *",
            "is_scheduled": "1",
            "dispatch.earliest_time": "-1m@m",
            "dispatch.latest_time": "@m",
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.severity": "4",
            "alert.suppress": "1",
            "alert.suppress.period": "5m",
            "action.webhook": "1",
            "action.webhook.param.url": WEBHOOK_URL
        }
        local_rules[rule_name] = payload
    return local_rules


def create_or_update_rule(rule_name, payload, exists):
    data = payload.copy()
    if exists and "name" in data:
        del data["name"]

    try:
        url = f"{API_BASE_URL}/{rule_name}" if exists else API_BASE_URL
        res = requests.post(url, headers=HEADERS, data=data, verify=False, timeout=30)
        if res.status_code in (200, 201):
            logger.info(f"UĞURLU: {rule_name} {'yeniləndi' if exists else 'yaradıldı'}.")
        else:
            logger.error(f"XƏTA: {rule_name} emal edilmədi! Status: {res.status_code} - {res.text}")
    except Exception as e:
        logger.error(f"XƏTA: Qayda {rule_name} işlənərkən problem yaşandı: {e}")


def delete_rule(rule_name):
    try:
        res = requests.delete(f"{API_BASE_URL}/{rule_name}", headers=HEADERS, verify=False, timeout=30)
        if res.status_code == 200:
            logger.info(f"SİLİNDİ: {rule_name}")
    except Exception as e:
        logger.error(f"XƏTA: {rule_name} silinərkən problem yaşandı: {e}")


def main():
    logger.info("==== Splunk SIEM Detection Rules Deployment Process Started ====")
    existing_rules = get_existing_rules()
    local_rules = read_local_rules()

    for rule_name, payload in local_rules.items():
        create_or_update_rule(rule_name, payload, rule_name in existing_rules)

    for rule_name in existing_rules:
        if rule_name not in local_rules:
            delete_rule(rule_name)
            
    logger.info("==== Deployment Process Successfully Completed ====")


if __name__ == "__main__":
    main()
