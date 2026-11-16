import os
import requests
import urllib3
from pathlib import Path
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
env_path = BASE_DIR / "configure.env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()


class WazuhIndexerClient:
    """Client kết nối tới Wazuh Indexer (Port 9200) để lấy security alerts thực tế"""

    def __init__(self):
        self.host = os.getenv("INDEXER_HOST", "localhost")
        self.port = os.getenv("INDEXER_PORT", "9200")
        self.username = os.getenv("INDEXER_USERNAME", "admin")
        self.password = os.getenv("INDEXER_PASSWORD", "")
        self.verify_ssl = os.getenv("INDEXER_VERIFY_SSL", "false").lower() == "true"
        self.base_url = f"https://{self.host}:{self.port}"

    def test_connection(self):
        """Kiểm tra kết nối và đăng nhập tới Indexer"""
        try:
            r = requests.get(
                self.base_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=5
            )
            return r.status_code == 200, r.json() if r.status_code == 200 else f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    def get_recent_alerts(self, size: int = 10, min_level: int = 3):
        """Lấy các alert mới nhất từ index wazuh-alerts-*"""
        if not self.password:
            return []

        url = f"{self.base_url}/wazuh-alerts-*/_search"
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "range": {
                    "rule.level": {
                        "gte": min_level
                    }
                }
            }
        }

        try:
            response = requests.post(
                url,
                json=query,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=10
            )
            if response.status_code == 200:
                hits = response.json().get("hits", {}).get("hits", [])
                alerts = []
                for h in hits:
                    item = h.get("_source", {})
                    item["_alert_id"] = h.get("_id")
                    alerts.append(item)
                return alerts
            else:
                return []
        except Exception as e:
            print(f"[!] Không thể kéo alerts từ Indexer: {e}")
            return []
