asdimport os
import glob
import requests
import logging
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://9.223.115.161:8089")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
APP_CONTEXT = "search"
OWNER = "nobody"

# Mərkəzləşdirilmiş Telegram Alert Konfiqurasiyası
TELEGRAM_TOKEN = "8875580959:AAEOvW7ZPzygkQwxc2vfsJT-FZt3P5jwCDc"
TELEGRAM_CHAT_ID = "-1004353279755"
WEBHOOK_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage?chat_id={TELEGRAM_CHAT_ID}&parse_mode=HTML&text=%F0%9F%9A%A8%20%3Cb%3EMilliBlueSec%20SIEM%20Alert%3C%2Fb%3E%20%F0%9F%9A%A8%0A%0A%3Cb%3ERule%20Name%3A%3C%2Fb%3E%20%24name%24%0A%3Cb%3EAttack%20Type%3A%3C%2Fb%3E%20%24result.attack_type%24%0A%3Cb%3ESource%20IP%3A%3C%2Fb%3E%20%24result.src_ip%24%0A%3Cb%3EDestination%3A%3C%2Fb%3E%20%24result.dest%24%0A%3Cb%3EURI%3A%3C%2Fb%3E%20%24result.uri%24%0A%3Cb%3EHTTP%20Method%3A%3C%2Fb%3E%20%24result.http_method%24%0A%3Cb%3ESeverity%3A%3C%2Fb%3E%20%24result.severity%24%0A%3Cb%3ETime%3A%3C%2Fb%3E%20%24result.time_formatted%24%0A%3Cb%3EHost%3A%3C%2Fb%3E%20%24result.host%24%0A%3Cb%3EIndex%3A%3C%2Fb%3E%20%24result.index%24%0A%3Cb%3ERecommendation%3A%3C%2Fb%3E%20%24result.recommendation%24"

if not SPLUNK_TOKEN:
    logger.error("CRITICAL: SPLUNK_TOKEN mühit dəyişəni tapılmadı! Deployment dayandırılır.")
    sys.exit(1)

HEADERS = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
API_BASE_URL = f"{SPLUNK_HOST}/servicesNS/{OWNER}/{APP_CONTEXT}/saved/searches"


def get_existing_rules():
    params = {"output_mode": "json", "count": 0, "search": "name=SPL-OWASP-*"}
    try:
        res = requests.get(API_BASE_URL, headers=HEADERS, params=params, verify=False, timeout=30)
        res.raise_for_status()
        return {entry["name"]: entry for entry in res.json().get("entry", [])}
    except requests.exceptions.RequestException as e:
        logger.error(f"Splunk API xətası: {e}")
        sys.exit(1)


def read_local_rules():
    local_rules = {}
    # Artıq .json əvəzinə təmiz SPL saxlayan .conf faylları axtarılır
    for file_path in glob.glob("rules/splunk/*.conf"):
        rule_name = os.path.basename(file_path).replace(".conf", "")
        with open(file_path, "r", encoding="utf-8") as f:
            spl_query = f.read().strip()
        
        if not spl_query:
            continue

        # Splunk REST API üçün payload dinamik formalaşdırılır
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
            "alert.suppress.fields": "src_ip",
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
