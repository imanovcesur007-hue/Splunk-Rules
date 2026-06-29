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
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
APP_CONTEXT = "search"
OWNER = "nobody"

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
    search_path = "rules/splunk/*.conf"
    # Debug üçün axtarış yolunu çap edirik
    logger.info(f"Axtarış aparılan qovluq: {os.getcwd()}")
    files = glob.glob(search_path)
    logger.info(f"Tapılan fayllar: {files}") # <--- Bu sətir problemin kökünü açacaq
    
    if not files:
        logger.warning(f"Heç bir fayl tapılmadı! Axtarış yolu: {search_path}")
        return local_rules
    # ... qalan kod olduğu kimi qalır
