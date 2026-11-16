import os
import requests
import urllib3
from pathlib import Path
from dotenv import load_dotenv

# Tìm chính xác file configure.env ở thư mục gốc AI_Prompt
BASE_DIR = Path(__file__).resolve().parent.parent.parent
env_path = BASE_DIR / "configure.env"

if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

# Tắt cảnh báo SSL cho môi trường Lab/Self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhAPIClient:
    def __init__(self):
        self.host = os.getenv("WAZUH_HOST")
        self.port = os.getenv("WAZUH_API_PORT", "55000")
        self.username = os.getenv("WAZUH_USERNAME")
        self.password = os.getenv("WAZUH_PASSWORD")
        self.verify_ssl = (
            os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"
        )

        if not self.host or not self.username or not self.password:
            raise ValueError(
                f"[!] Thiếu thông tin cấu hình trong configure.env!\n"
                f"    HOST: {self.host}, USERNAME: {self.username}, FILE: {env_path}"
            )

        self.base_url = f"https://{self.host}:{self.port}"
        self.token = None

        self.session = requests.Session()
        self.session.verify = self.verify_ssl

    def authenticate(self):
        url = f"{self.base_url}/security/user/authenticate"
        print(f"[*] Đang xác thực với Wazuh API tại: {url} ...")

        try:
            response = self.session.post(
                url,
                params={"raw": "true"},
                auth=(self.username, self.password),
                timeout=15
            )
            response.raise_for_status()

            # Xử lý token (cả trường hợp trả về raw text hoặc JSON)
            try:
                data = response.json()
                self.token = data.get("data", {}).get("token", response.text.strip())
            except Exception:
                self.token = response.text.strip()

            print("[+] Xác thực Wazuh API thành công! Đã lấy được JWT Token.")

        except requests.exceptions.SSLError as e:
            raise Exception(f"[!] Lỗi SSL Certificate: {e}")
        except requests.exceptions.ConnectionError as e:
            raise Exception(
                f"[!] Không thể kết nối tới {self.base_url}. Hãy kiểm tra xem Wazuh Manager có đang bật port {self.port} không hoặc firewall có chặn không. Lỗi: {e}"
            )
        except requests.exceptions.HTTPError as e:
            raise Exception(f"[!] Lỗi HTTP từ Wazuh (Sai username/password hoặc không đủ quyền): {e}")

    def get(self, endpoint):
        if not self.token:
            self.authenticate()

        url = f"{self.base_url}{endpoint}"
        response = self.session.get(
            url,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=15
        )
        response.raise_for_status()
        return response.json()

    def get_manager_info(self):
        return self.get("/manager/info")
