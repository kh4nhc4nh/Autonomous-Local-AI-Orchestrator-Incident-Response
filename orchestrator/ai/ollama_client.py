import os
import requests
import json
import re
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
env_path = BASE_DIR / "configure.env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()


class OllamaClient:
    def __init__(self):
        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        self.model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
        self.api_generate_url = f"{self.base_url}/api/generate"
        self.api_tags_url = f"{self.base_url}/api/tags"

    def test_connection(self):
        """Kiểm tra xem Ollama có phản hồi không và liệt kê models"""
        try:
            res = requests.get(self.api_tags_url, timeout=5)
            if res.status_code == 200:
                data = res.json()
                models = [m.get("name") for m in data.get("models", [])]
                print(f"[+] Kết nối Ollama thành công tại {self.base_url}!")
                print(f"[+] Các model hiện có trên máy AI: {models}")
                return True, models
            return False, f"HTTP Error {res.status_code}"
        except Exception as e:
            return False, str(e)

    def _build_fallback_report(self, scenario_type: str, events: list) -> str:
        """Tạo báo cáo dự phòng chuẩn SOC đầy đủ chi tiết khi AI không phản hồi kịp"""
        if not events:
            return "⚠️ Không có dữ liệu cảnh báo để hiển thị."

        first = events[0]
        rule_desc = first.get("rule_description", "Unknown Alert")
        rule_id = first.get("rule_id", "N/A")
        level = first.get("rule_level", 0)
        net = first.get("network", {})
        src = net.get("source", "Local Console")
        dst = net.get("destination", first.get("agent", "Unknown"))
        protocol = net.get("protocol", "Local")
        action = first.get("action_detail") or first.get("process", {}).get("command_line", "N/A")
        mitre_ids = ", ".join(first.get("mitre", {}).get("ids", [])) or "N/A"
        mitre_tactics = ", ".join(first.get("mitre", {}).get("tactics", [])) or "Unclassified"
        target_usr = first.get("target_user", "")

        if scenario_type == "MULTI_STAGE_ATTACK":
            timeline_lines = []
            for idx, ev in enumerate(events, 1):
                ev_rid = ev.get("rule_id", "N/A")
                ev_lvl = ev.get("rule_level", 0)
                ev_act = ev.get("action_detail") or ev.get("rule_description", "")
                ev_mitre = ", ".join(ev.get("mitre", {}).get("ids", [])) or "N/A"
                timeline_lines.append(f"{idx}. `Rule {ev_rid} (Level {ev_lvl})` ➔ {ev_act} | MITRE: `{ev_mitre}`")
            timeline_str = "\n".join(timeline_lines)

            return (
                f"⛓️ *PHÁT HIỆN CHUỖI TẤN CÔNG (MULTI-STAGE ATTACK)*\n"
                f"• *Mục tiêu:* `{src}` ➔ `{dst}`\n"
                f"⏱️ *Timeline các bước của hacker:*\n{timeline_str}\n"
                f"🎯 *Ý đồ tấn công:* Kẻ tấn công đang phối hợp nhiều kỹ thuật leo thang đặc quyền để chiếm quyền điều khiển hệ thống.\n"
                f"🛡️ *Phương án ngăn chặn chuỗi tấn công:*\n"
                f"• *Xử lý tức thì:* `netsh advfirewall set allprofiles state on` & cô lập ngay host nạn nhân.\n"
                f"• *Phòng ngừa lây lan:* Thu hồi các tài khoản vừa được tạo, quét các tiến trình ngầm và kiểm tra toàn bộ kết nối mạng outbound."
            )

        elif scenario_type == "CRITICAL_SINGLE_ALERT":
            remediation_cmd = f"net user {target_usr} /active:no" if target_usr and target_usr != "N/A" else "netsh advfirewall firewall add rule name='Block-Threat' dir=in action=block"
            return (
                f"🚨 *BÁO ĐỘNG ĐỎ: {rule_desc} | Rule {rule_id} (Level {level})*\n"
                f"• *Tuyến mạng:* `{src}` ➔ `{dst}`\n"
                f"• *Giao thức/Truy cập:* {protocol}\n"
                f"• *Hành vi chi tiết:* {action}\n"
                f"• *MITRE ATT&CK:* `{mitre_ids}` - {mitre_tactics}\n"
                f"🎯 *DỰ ĐOÁN HACKER SẼ LÀM GÌ TIẾP THEO:*\n"
                f"- Đăng nhập RDP từ xa hoặc triển khai backdoor ngầm để giữ kết nối\n"
                f"- Vô hiệu hóa Antivirus và xóa sạch nhật ký Windows Event Log\n"
                f"🛡️ *Phương án ngăn chặn khẩn cấp:*\n"
                f"• *Xử lý tức thì:* `{remediation_cmd}`\n"
                f"• *Phòng ngừa tái diễn:* Bật chính sách Audit Account Management và giới hạn quyền thành viên Local Administrators qua GPO."
            )

        elif scenario_type == "RECONNAISSANCE_BURST":
            commands_summary = []
            for ev in events:
                cmd_act = ev.get("action_detail") or ev.get("process", {}).get("command_line", "Unknown Command")
                rid = ev.get("rule_id", "N/A")
                lvl = ev.get("rule_level", 0)
                commands_summary.append(f"- `{cmd_act}` (Rule {rid} - Level {lvl})")
            commands_str = "\n".join(commands_summary)
            actor = first.get("actor_user", "Local User")
            session_id = first.get("session_id", "N/A")

            return (
                f"🔍 *PHÁT HIỆN ĐỢT RÀ QUÉT TRINH SÁT (RECONNAISSANCE BURST)*\n"
                f"• *Đối tượng thực hiện:* `{actor}` trên máy `{dst}`\n"
                f"• *Phiên làm việc (Session):* `{session_id}`\n"
                f"⏱️ *Tổng hợp các lệnh trinh sát đã thực thi:*\n{commands_str}\n"
                f"🎯 *Đánh giá nguy cơ:* Đối tượng đang thu thập thông tin cấu hình/tài khoản hệ thống (Discovery). Chưa ghi nhận dấu hiệu leo thang đặc quyền hay phá hoại.\n"
                f"🛡️ *Khuyến nghị giám sát:*\n"
                f"• *Hành động:* Giám sát chặt chẽ phiên làm việc; sẵn sàng cô lập nếu phát hiện lệnh leo thang (RunAs, PrivEsc) hoặc kết nối C2 ra ngoài.\n"
                f"• *Lệnh kiểm tra:* `Get-Process -IncludeUserName | Where-Object {{ $_.UserName -like '*{actor}*' }}`"
            )

        else:
            return (
                f"⚠️ *CẢNH BÁO BẢO MẬT | Rule {rule_id} (Level {level})*\n"
                f"• *Mục tiêu:* `{src}` ➔ `{dst}`\n"
                f"• *Giao thức/Dịch vụ:* {protocol}\n"
                f"• *Hành vi bắt được:* {action}\n"
                f"• *MITRE ATT&CK:* `{mitre_ids}` - {mitre_tactics}\n"
                f"🛡️ *Phương án ngăn chặn:* Kiểm tra tính hợp lệ của tài khoản thực hiện. Nếu là truy cập trái phép, lập tức vô hiệu hóa phiên làm việc."
            )

    def analyze_alert(self, scenario_type: str, events_context: list, system_prompt: str) -> str:
        """Gửi alert context sang Local AI để phân tích chuyên sâu"""
        user_prompt = f"""Hãy phân tích cảnh báo bảo mật sau theo đúng MẪU tương ứng trong System Prompt:
Kịch bản: {scenario_type}
Dữ liệu Alert chi tiết:
{json.dumps(events_context, indent=2, ensure_ascii=False)}
"""

        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "top_p": 0.9,
                "num_predict": 500
            }
        }

        try:
            response = requests.post(self.api_generate_url, json=payload, timeout=60)
            if response.status_code == 200:
                data = response.json()
                ai_text = data.get("response", "").strip()

                # Cắt bỏ mọi câu tiếng Trung dư thừa nếu mô hình Qwen sinh ra ở cuối
                ai_text = re.sub(r'[\u4e00-\u9fff]+.*', '', ai_text).strip()

                # Nếu AI trả về rỗng vì bất kỳ lý do gì, dùng fallback chuẩn SOC
                if not ai_text:
                    ai_text = self._build_fallback_report(scenario_type, events_context)
                return ai_text
            else:
                return self._build_fallback_report(scenario_type, events_context)
        except Exception:
            # Fallback nếu kết nối mạng tới máy AI có độ trễ
            return self._build_fallback_report(scenario_type, events_context)
