import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import yaml
from collectors.wazuh_api_client import WazuhAPIClient
from collectors.wazuh_indexer_client import WazuhIndexerClient
from ai.ollama_client import OllamaClient
from processors.alert_parser import AlertParser
from processors.state_tracker import AttackStateTracker
from notifiers.telegram_notifier import TelegramNotifier


def load_system_prompt():
    prompt_file = BASE_DIR / "config" / "system_prompt.txt"
    if prompt_file.exists():
        with open(prompt_file, "r", encoding="utf-8") as f:
            return f.read()
    return "Bạn là Cyber Security AI Analyst chuyên phân tích logs."


def load_rules():
    rules_file = BASE_DIR / "config" / "rules.yaml"
    if rules_file.exists():
        with open(rules_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


def main():
    print("=" * 65)
    print("      HỆ THỐNG AI SOC ORCHESTRATOR - GIÁM SÁT THỜI GIAN THỰC")
    print("=" * 65)

    # Tải Rules & System Prompt
    system_prompt = load_system_prompt()
    rules = load_rules()
    detection_rules = rules.get("detection_rules", {})
    min_alert_level = detection_rules.get("min_alert_level", 5)
    critical_alert_level = detection_rules.get("critical_alert_level", 10)
    multi_threshold = detection_rules.get("multi_event_threshold", 2)
    ignored_rule_ids = set(str(rid) for rid in detection_rules.get("ignored_rule_ids", []))
    high_risk_tactics = detection_rules.get("high_risk_tactics", [])
    monitored_lolbins = detection_rules.get("monitored_lolbins", [])
    flag_network = detection_rules.get("flag_network_anomalies", True)

    print(f"[*] Bộ lọc kích hoạt: Chỉ phân tích Alert từ Level {min_alert_level} trở lên.")
    print(f"[*] Ngưỡng Critical: Level {critical_alert_level} (AI sẽ dự đoán bước hacker đi tiếp).")
    print(f"[*] Đã nạp {len(ignored_rule_ids)} Rule ID rác vào danh sách bỏ qua (Noise filter).")
    print(f"[*] Giám sát {len(high_risk_tactics)} Chiến thuật MITRE ATT&CK nguy hiểm cao.")
    print(f"[*] Giám sát {len(monitored_lolbins)} công cụ LOLBins (Living-off-the-Land).")

    # 1. Kiểm tra Wazuh Manager API (Port 55000)
    print("\n[1] Kiểm tra Wazuh Manager API (Port 55000)...")
    try:
        wazuh_client = WazuhAPIClient()
        mgr_info = wazuh_client.get_manager_info()
        print(f"[+] Wazuh Manager OK! Phiên bản: {mgr_info['data']['affected_items'][0]['version']}")
    except Exception as e:
        print(f"[-] Lỗi kết nối Wazuh API: {e}")

    # 2. Kiểm tra Wazuh Indexer (Port 9200)
    print("\n[2] Kiểm tra Wazuh Indexer Alerts (Port 9200)...")
    indexer_client = WazuhIndexerClient()
    idx_ok, idx_info = indexer_client.test_connection()
    if idx_ok:
        print(f"[+] Wazuh Indexer OK! Cluster: {idx_info.get('cluster_name')} (OpenSearch)")
    else:
        print(f"[-] Lỗi kết nối Indexer: {idx_info}")

    # 3. Kiểm tra Local AI Machine (Port 11434)
    ai_client = OllamaClient()
    print(f"\n[3] Kiểm tra AI Machine ({ai_client.base_url})...")
    ai_ok, models = ai_client.test_connection()
    if ai_ok:
        print(f"[+] AI Machine OK! Models khả dụng: {models}")
    else:
        print(f"[!] Lỗi kết nối AI: {models}")

    # 4. Kiểm tra Telegram Notifier
    print("\n[4] Kiểm tra Telegram Notifier...")
    telegram = TelegramNotifier()
    if telegram.is_configured():
        print(f"[+] Telegram Notifier OK! Chat ID: {telegram.chat_id}")
    else:
        print("[!] Telegram Notifier chưa cấu hình.")

    tracker = AttackStateTracker(
        window_minutes=detection_rules.get("correlation_window_minutes", 10),
        critical_alert_level=critical_alert_level,
        multi_event_threshold=multi_threshold,
        high_risk_tactics=high_risk_tactics,
        monitored_lolbins=monitored_lolbins,
        flag_network_anomalies=flag_network,
        dedup_window_seconds=detection_rules.get("dedup_window_seconds", 15)
    )

    print("\n" + "=" * 65)
    print("   KHỞI ĐỘNG VÒNG LẶP CANH GÁC REAL-TIME (ENTITY-BASED CORRELATION)")
    print("   (Hệ thống đang chạy nền, bấm Ctrl + C để dừng)")
    print("=" * 65)

    # Đánh dấu các alert cũ đã có trong quá khứ để không phân tích lại hàng loạt
    print("[*] Đang khởi tạo bộ nhớ để chỉ bắt các Alert MỚI sinh ra...")
    initial_alerts = indexer_client.get_recent_alerts(size=50, min_level=min_alert_level)
    processed_alert_ids = set()
    for a in initial_alerts:
        aid = a.get("_alert_id") or a.get("id")
        if aid:
            processed_alert_ids.add(aid)
    print(f"[+] Đã ghi nhớ {len(processed_alert_ids)} alert cũ. Đang canh gác...")

    poll_interval = 3  # Quét mỗi 3 giây

    while True:
        try:
            # Chỉ kéo các alert từ min_alert_level trở lên
            recent_alerts = indexer_client.get_recent_alerts(size=10, min_level=min_alert_level)
            
            # Lọc các alert mới xuất hiện
            new_alerts = []
            for alert in recent_alerts:
                aid = alert.get("_alert_id") or alert.get("id")
                rule = alert.get("rule", {})
                rule_id = str(rule.get("id", ""))

                # Bỏ qua nếu nằm trong danh sách ignored_rule_ids (Noise filter)
                if rule_id in ignored_rule_ids:
                    continue

                if aid and aid not in processed_alert_ids:
                    processed_alert_ids.add(aid)
                    new_alerts.append(alert)

            # Xử lý các alert mới
            if new_alerts:
                new_alerts.reverse()

                impacted_sessions = []
                for raw_alert in new_alerts:
                    # 1. Bóc tách và làm sạch chuyên sâu dữ liệu Alert
                    clean_alert = AlertParser.parse(raw_alert)
                    session_key = tracker.ingest(clean_alert)
                    if session_key not in impacted_sessions:
                        impacted_sessions.append(session_key)

                    print(f"\n[🚨 PHÁT HIỆN ALERT] Rule {clean_alert.get('rule_id')} (Level {clean_alert.get('rule_level')}) | {clean_alert.get('rule_description')}")
                    print(f"   • Entity Session: [{session_key}]")
                    print(f"   • Tuyến: {clean_alert.get('network', {}).get('source')} ➔ {clean_alert.get('network', {}).get('destination')}")
                    print(f"   • Chi tiết: {clean_alert.get('action_detail')}")

                # 2. Đánh giá mối đe dọa chuyên biệt trên từng Entity Session
                for session_key in impacted_sessions:
                    scenario_type, context_events = tracker.evaluate_session(session_key)

                    if scenario_type != "NO_ALERT" and context_events:
                        print(f"[*] Kịch bản xác định [{session_key}]: [{scenario_type}] (Gồm {len(context_events)} sự kiện)")
                        print(f"[*] Đang gửi sang máy AI ({ai_client.model}) phân tích...")

                        ai_report = ai_client.analyze_alert(
                            scenario_type=scenario_type,
                            events_context=context_events,
                            system_prompt=system_prompt
                        )

                        print("\n" + "-" * 50)
                        print(ai_report)
                        print("-" * 50)

                        # 3. Gửi báo cáo về Telegram
                        telegram.send_report(ai_report)
                        print("[+] Đã gửi báo cáo phân tích thành công về Telegram của bạn!")

                        # Nếu là chuỗi tấn công hoặc đợt rà quét đã báo cáo xong thì xóa bucket của session đó
                        if scenario_type in ["MULTI_STAGE_ATTACK", "RECONNAISSANCE_BURST"]:
                            tracker.clear_session(session_key)

            time.sleep(poll_interval)

        except KeyboardInterrupt:
            print("\n[*] Đã dừng giám sát an toàn. Tạm biệt!")
            break
        except Exception as e:
            print(f"[!] Lỗi trong vòng lặp giám sát: {e}")
            time.sleep(poll_interval)


if __name__ == "__main__":
    main()
