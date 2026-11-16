import os
import requests
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
env_path = BASE_DIR / "configure.env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()


class TelegramNotifier:
    def __init__(self):
        self.token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def is_configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def send_report(self, text: str):
        """Gửi báo cáo bảo mật về Telegram"""
        if not self.is_configured():
            print("[*] (Telegram chưa cấu hình Token/Chat_ID. Báo cáo sẽ hiển thị trên Terminal)")
            return

        # Giới hạn tin nhắn của Telegram là 4096 ký tự
        max_chunk = 4000
        chunks = [text[i:i + max_chunk] for i in range(0, len(text), max_chunk)]

        for chunk in chunks:
            payload = {
                "chat_id": self.chat_id,
                "text": chunk,
                "parse_mode": "Markdown"
            }
            try:
                res = requests.post(self.api_url, json=payload, timeout=10)
                if res.status_code != 200:
                    # Nếu lỗi parse Markdown của Telegram, fallback gửi plain text
                    payload.pop("parse_mode", None)
                    requests.post(self.api_url, json=payload, timeout=10)
            except Exception as e:
                print(f"[!] Lỗi kết nối Telegram: {e}")

