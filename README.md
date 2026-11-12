# 🛡️ AI SOC Wazuh Orchestrator

Hệ thống **AI SOC Analyst tự động hóa** kết nối đa thiết bị: Tự động thu thập Security Alerts từ **Wazuh**, xâu chuỗi sự kiện tấn công (Attack Correlation), sử dụng **Local AI (Ollama Qwen2.5-3B)** để phân tích, dự đoán bước tiếp theo của hacker, và gửi báo cáo trực tiếp về **Telegram**.

---

## 🏗️ Kiến Trúc Hệ Thống (3 Thiết Bị)

```
┌─────────────────────────────────┐
│     Wazuh Manager (Ubuntu)       │  (192.168.100.220)
│   • API Management: Port 55000  │
│   • Indexer Alerts: Port 9200   │
└────────────────┬────────────────┘
                 │ (1) Kéo Alert mới nhất theo thời gian thực
                 ▼
┌─────────────────────────────────┐
│     MÁY BẠN: ORCHESTRATOR       │  (Chạy Python cực nhẹ ~30MB RAM)
│   • Lọc rác & Token optimization│
│   • State Tracker (5-min window)│
└────────────────┬────────────────┘
                 │ (2) Gửi Alert Context qua mạng LAN (Port 11434)
                 ▼
┌─────────────────────────────────┐
│     MÁY AI: OLLAMA SERVER       │  (192.168.100.101)
│   • Model: Qwen2.5-3B           │
│   • Phân tích & Dự đoán hành vi │
└────────────────┬────────────────┘
                 │ (3) Bắn báo cáo phân tích
                 ▼
┌─────────────────────────────────┐
│     TELEGRAM BOT NOTIFIER       │ ──► [Điện thoại / Laptop của bạn]
│   • @khanh_soc_ai_bot           │
└─────────────────────────────────┘
```

---

## 📁 Cấu Trúc Thư Mục Dự Án

```
AI_Prompt/
│
├── configure.env                   # Cấu hình IP, Port, Token và Password bảo mật
├── AI-SOC Wazuh Workflow...png     # Sơ đồ kiến trúc luồng dữ liệu
├── README.md                       # Tài liệu hướng dẫn dự án
│
└── orchestrator/                   # Mã nguồn chính của Orchestrator
    ├── main.py                     # File chạy chính (Vòng lặp canh gác 24/7)
    │
    ├── ai/
    │   └── ollama_client.py        # Module kết nối LAN sang máy AI (Chống Prompt Injection)
    │
    ├── collectors/
    │   ├── wazuh_api_client.py     # Module giao tiếp Wazuh Manager API (55000)
    │   └── wazuh_indexer_client.py # Module kéo Alert từ Wazuh Indexer (9200)
    │
    ├── config/
    │   ├── system_prompt.txt       # Prompt cấu hình nhân cách và rules phân tích của AI
    │   └── rules.yaml              # Danh sách lệnh cấm, ngưỡng cảnh báo, thời gian correlation
    │
    ├── notifiers/
    │   └── telegram_notifier.py    # Module gửi tin nhắn format Markdown về Telegram Bot
    │
    └── processors/
        ├── alert_parser.py         # Bộ lọc rác, cắt giảm 85% token cho AI
        └── state_tracker.py        # Bộ nhớ trượt (Sliding Window) xâu chuỗi tấn công
```

---

## 🚀 Hướng Dẫn Vận Hành

### 1. Khởi động vòng lặp giám sát:
```powershell
# Kích hoạt môi trường ảo (nếu chưa kích hoạt)
.\venv\Scripts\Activate.ps1

# Chạy hệ thống giám sát
python orchestrator\main.py
```

### 2. Tùy chỉnh quy tắc phân tích theo ý bạn:
- **Thay đổi phong cách / yêu cầu báo cáo của AI**: Chỉnh sửa file `orchestrator/config/system_prompt.txt`.
- **Thêm tiến trình nguy hiểm cần cảnh báo khẩn cấp**: Chỉnh sửa file `orchestrator/config/rules.yaml`.
