import os
import json
import glob
import requests
import logging
import sys
import urllib3

# Splunk Enterprise tərəfindən istifadə edilən self-signed sertifikat xəbərdarlıqlarını gizlədirik
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Professional logging konfiqurasiyası
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment Dəyişənləri (GitHub Actions tərəfindən ötürüləcək)
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://9.223.115.161:8089")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
APP_CONTEXT = "search"
OWNER = "nobody"

if not SPLUNK_TOKEN:
    logger.error("CRITICAL: SPLUNK_TOKEN mühit dəyişəni tapılmadı! Deployment dayandırılır.")
    sys.exit(1)

HEADERS = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}"
}

# Splunk Saved Searches REST API Endpoints
API_BASE_URL = f"{SPLUNK_HOST}/servicesNS/{OWNER}/{APP_CONTEXT}/saved/searches"


def get_existing_rules():
    """Splunk daxilindəki mövcud OWASP qaydalarını gətirir."""
    logger.info("Splunk API ilə əlaqə qurulur və mövcud qaydalar yoxlanılır...")
    params = {
        "output_mode": "json",
        "count": 0,
        "search": "name=SPL-OWASP-*"
    }
    try:
        response = requests.get(API_BASE_URL, headers=HEADERS, params=params, verify=False, timeout=30)
        response.raise_for_status()
        data = response.json()
        rules = {entry["name"]: entry for entry in data.get("entry", [])}
        logger.info(f"Splunk daxilində {len(rules)} ədəd mövcud 'SPL-OWASP' qaydası tapıldı.")
        return rules
    except requests.exceptions.RequestException as e:
        logger.error(f"Splunk API-dən məlumat alınarkən xəta baş verdi: {e}")
        sys.exit(1)


def read_local_rules():
    """Repository-də olan bütün JSON qaydalarını oxuyur."""
    logger.info("Local repository-dən qaydalar (rules/splunk/*.json) oxunur...")
    local_rules = {}
    files = glob.glob("rules/splunk/*.json")
    
    if not files:
        logger.warning("Heç bir JSON qayda faylı tapılmadı! 'rules/splunk/' qovluğunu yoxlayın.")
        return local_rules

    for file_path in files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                rule_data = json.load(f)
                rule_name = rule_data.get("name")
                
                if not rule_name:
                    logger.error(f"Fayl '{file_path}' daxilində 'name' parametri yoxdur. Nəzərə alınmır.")
                    continue
                
                if not rule_name.startswith("SPL-OWASP-"):
                    logger.warning(f"Qayda adı '{rule_name}' ('{file_path}') 'SPL-OWASP-' ilə başlamır. Nəzərə alınmır.")
                    continue

                local_rules[rule_name] = rule_data
        except Exception as e:
            logger.error(f"Fayl oxunarkən xəta baş verdi '{file_path}': {e}")
            
    logger.info(f"Repository daxilində {len(local_rules)} ədəd etibarlı qayda tapıldı.")
    return local_rules


def create_or_update_rule(rule_name, payload, exists):
    """Qaydanı Splunk API vasitəsilə yaradır və ya mövcuddursa yeniləyir."""
    # Məlumatları Splunk x-www-form-urlencoded formatına uyğunlaşdırırıq
    data = payload.copy()
    
    # Mövcud qaydanı yeniləyərkən 'name' parametrini payload-dan çıxarırıq (URL-də onsuz da var)
    if exists and "name" in data:
        del data["name"]

    try:
        if exists:
            logger.info(f"Mövcud qayda yenilənir: {rule_name}")
            url = f"{API_BASE_URL}/{rule_name}"
            response = requests.post(url, headers=HEADERS, data=data, verify=False, timeout=30)
        else:
            logger.info(f"Yeni qayda yaradılır: {rule_name}")
            url = API_BASE_URL
            response = requests.post(url, headers=HEADERS, data=data, verify=False, timeout=30)
        
        if response.status_code in (200, 201):
            logger.info(f"UĞURLU: {rule_name} (Status: {response.status_code})")
        else:
            logger.error(f"XƏTA: {rule_name} emal edilə bilmədi! Status: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"XƏTA: Qayda {rule_name} işlənərkən xəta baş verdi: {e}")


def delete_rule(rule_name):
    """Local repository-də olmayan, amma Splunk-da qalan qaydanı silir."""
    logger.info(f"Mövcudluğunu itirmiş qayda Splunk-dan silinir: {rule_name}")
    url = f"{API_BASE_URL}/{rule_name}"
    try:
        response = requests.delete(url, headers=HEADERS, verify=False, timeout=30)
        if response.status_code == 200:
            logger.info(f"SİLİNDİ: {rule_name}")
        else:
            logger.error(f"XƏTA: {rule_name} silinə bilmədi! Status: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"XƏTA: Qayda {rule_name} silinərkən xəta baş verdi: {e}")


def main():
    logger.info("==== Splunk SIEM Detection Rules Deployment Process Started ====")
    
    existing_rules = get_existing_rules()
    local_rules = read_local_rules()

    # Yaratmaq və Yeniləmək
    for rule_name, rule_payload in local_rules.items():
        exists = rule_name in existing_rules
        create_or_update_rule(rule_name, rule_payload, exists)

    # Silmək (Cleanup)
    for rule_name in existing_rules:
        if rule_name not in local_rules:
            delete_rule(rule_name)
            
    logger.info("==== Deployment Process Successfully Completed ====")


if __name__ == "__main__":
    main()
