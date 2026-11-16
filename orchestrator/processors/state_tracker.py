from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional


class AttackStateTracker:
    """
    Hệ thống Theo dõi Trạng thái và Tương quan Tấn công Đa chiều (Multi-Dimensional Correlation Engine)
    Tuân thủ nguyên tắc SOC & Cyber Kill Chain:
    1. Entity-Based Isolation: Phân vùng theo từng Session / Actor độc lập.
    2. Event Deduplication: Tự động gom các alert lặp lại liên tiếp (Noise Aggregation) như Windows Update hay OneDrive.
    3. MITRE Tactic Progression: Phân biệt rõ:
       - RECONNAISSANCE_BURST: Khi các sự kiện đều thuộc giai đoạn Discovery (whoami, net user, systeminfo, ...)
       - MULTI_STAGE_ATTACK: Khi chuỗi sự kiện vượt qua >= 2 Chiến thuật MITRE khác nhau hoặc có quan hệ phả hệ cha-con kèm hành vi nguy hiểm.
       - CRITICAL_SINGLE_ALERT: Một sự kiện đơn lẻ mang tính phá hoại / leo thang cao (Rule Level >= 10 hoặc High Risk Tactic).
       - SINGLE_ALERT: Một sự kiện cảnh báo mức vừa.
    """

    DEFAULT_HIGH_RISK_TACTICS = [
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Impact",
        "Lateral Movement",
        "Command and Control"
    ]

    DEFAULT_RECON_TACTICS = [
        "Discovery",
        "Reconnaissance"
    ]

    def __init__(
        self,
        window_minutes: int = 10,
        critical_alert_level: int = 10,
        multi_event_threshold: int = 2,
        high_risk_tactics: Optional[List[str]] = None,
        monitored_lolbins: Optional[List[str]] = None,
        flag_network_anomalies: bool = True,
        dedup_window_seconds: int = 15
    ):
        self.window_seconds = window_minutes * 60
        self.critical_alert_level = critical_alert_level
        self.multi_event_threshold = multi_event_threshold
        self.high_risk_tactics = high_risk_tactics or self.DEFAULT_HIGH_RISK_TACTICS
        self.recon_tactics = self.DEFAULT_RECON_TACTICS
        self.monitored_lolbins = monitored_lolbins or []
        self.flag_network_anomalies = flag_network_anomalies
        self.dedup_window_seconds = dedup_window_seconds

        # Phân vùng lưu trữ theo Session Key: Dict[session_key, List[event_records]]
        self.session_buckets: Dict[str, List[Dict[str, Any]]] = {}

    def ingest(self, alert: Dict[str, Any]) -> str:
        """
        Nạp alert vào đúng khoang phiên (Session Bucket).
        Khử trùng lặp (Deduplication) nếu sự kiện tương tự vừa xảy ra trong vòng dedup_window_seconds.
        """
        now = datetime.now(timezone.utc)
        session_key = alert.get("session_key", "default_lane")

        if session_key not in self.session_buckets:
            self.session_buckets[session_key] = []

        bucket = self.session_buckets[session_key]

        # Kiểm tra Deduplication: Nếu cùng rule_id và cùng action/image phát sinh gần nhau
        if bucket:
            last_record = bucket[-1]
            last_alert = last_record["data"]
            last_time = last_record["received_at"]

            is_same_rule = str(last_alert.get("rule_id")) == str(alert.get("rule_id"))
            is_same_image = last_alert.get("process", {}).get("image") == alert.get("process", {}).get("image")
            time_diff = (now - last_time).total_seconds()

            if is_same_rule and is_same_image and time_diff <= self.dedup_window_seconds:
                # Tăng bộ đếm lặp lại thay vì đẩy thêm 1 record thừa
                last_record["repeat_count"] = last_record.get("repeat_count", 1) + 1
                last_record["received_at"] = now
                last_alert["repeat_count"] = last_record["repeat_count"]
                self._purge_old_events(now)
                return session_key

        bucket.append({
            "received_at": now,
            "data": alert,
            "repeat_count": 1
        })

        self._purge_old_events(now)
        return session_key

    def _purge_old_events(self, now: datetime):
        """Xóa các alert đã trôi qua khỏi cửa sổ thời gian (Correlation Window)"""
        empty_keys = []
        for key, bucket in self.session_buckets.items():
            valid_events = [
                item for item in bucket
                if (now - item["received_at"]).total_seconds() <= self.window_seconds
            ]
            if valid_events:
                self.session_buckets[key] = valid_events
            else:
                empty_keys.append(key)

        for key in empty_keys:
            del self.session_buckets[key]

    def _is_critical_threat(self, alert: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Đánh giá mức độ nguy hiểm dựa trên:
        1. Wazuh Rule Level (Level >= critical_alert_level)
        2. Chiến thuật hiểm yếu MITRE ATT&CK (Privilege Escalation, Defense Evasion, v.v.)
        3. Hành vi bất thường từ LOLBins
        """
        rule_level = alert.get("rule_level", 0)
        mitre_tactics = alert.get("mitre", {}).get("tactics", [])
        is_lolbin = alert.get("process", {}).get("is_lolbin", False)
        is_system = alert.get("is_system_account", False)

        # 1. Wazuh Rule Level cao (Level 10 - 15)
        if rule_level >= self.critical_alert_level:
            return True, f"Wazuh Rule Level {rule_level} đạt ngưỡng báo động đỏ"

        # 2. Thuộc các chiến thuật MITRE ATT&CK nguy hiểm cao
        matched_tactics = [t for t in mitre_tactics if t in self.high_risk_tactics]
        if matched_tactics:
            return True, f"Kỹ thuật thuộc Chiến thuật MITRE: {', '.join(matched_tactics)}"

        # 3. Tiến trình LOLBin được thực thi bởi user thường với Level >= 7
        if is_lolbin and not is_system and rule_level >= 7:
            return True, "Hành vi thực thi LOLBin từ người dùng ngoài luồng quản trị"

        return False, ""

    def _has_process_lineage(self, events: List[Dict[str, Any]]) -> bool:
        """
        Kiểm tra quan hệ phả hệ cha-con (Parent-Child Causal Lineage) giữa các sự kiện:
        - Tiến trình con có PPID bằng PID của tiến trình cha trong chuỗi
        - Hoặc ParentImage của tiến trình sau khớp với Image của tiến trình trước
        """
        for i in range(len(events) - 1):
            parent = events[i].get("process", {})
            child = events[i + 1].get("process", {})

            parent_pid = parent.get("pid")
            child_ppid = child.get("ppid")

            if parent_pid and child_ppid and parent_pid != "N/A" and child_ppid != "N/A":
                if str(parent_pid) == str(child_ppid):
                    return True

            parent_img = (parent.get("image") or "").lower()
            child_parent_img = (child.get("parent_image") or "").lower()
            if parent_img and child_parent_img and parent_img != "n/a" and child_parent_img != "n/a":
                if parent_img.endswith(child_parent_img) or child_parent_img.endswith(parent_img):
                    return True

        return False

    def evaluate_session(self, session_key: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Bộ máy đánh giá tương quan thông minh (Correlation Engine):
        - 'MULTI_STAGE_ATTACK': Chuỗi sự kiện tiến triển qua >= 2 chiến thuật MITRE khác nhau,
                                hoặc có quan hệ phả hệ tiến trình kết hợp hành vi nguy hiểm.
        - 'RECONNAISSANCE_BURST': Nhiều lệnh trinh sát/thăm dò liên tiếp (chỉ thuộc Discovery).
        - 'CRITICAL_SINGLE_ALERT': 1 sự kiện mang tính phá hoại / leo thang cao.
        - 'SINGLE_ALERT': 1 sự kiện thông thường.
        - 'NO_ALERT': Không có sự kiện.
        """
        if session_key not in self.session_buckets:
            return "NO_ALERT", []

        bucket = self.session_buckets[session_key]
        if not bucket:
            return "NO_ALERT", []

        events = [item["data"] for item in bucket]

        # Trường hợp 1 sự kiện đơn lẻ
        if len(events) == 1:
            single = events[0]
            is_critical, _ = self._is_critical_threat(single)
            if is_critical:
                return "CRITICAL_SINGLE_ALERT", [single]
            return "SINGLE_ALERT", [single]

        # Trường hợp có từ 2 sự kiện trở lên trong cùng 1 phiên
        # 1. Trích xuất tất cả các MITRE Tactics xuất hiện trong phiên
        all_tactics = set()
        for ev in events:
            tactics = ev.get("mitre", {}).get("tactics", [])
            for t in tactics:
                if t and t not in ["Benign Network Traffic", "Normal Activity", "Unclassified"]:
                    all_tactics.add(t)

        has_threat = any(self._is_critical_threat(ev)[0] for ev in events)
        is_pure_system = all(ev.get("is_system_account", False) for ev in events)
        has_lineage = self._has_process_lineage(events)

        # 2. Xử lý hoạt động định kỳ của hệ thống (Pure System Background Noise)
        if is_pure_system and not has_threat:
            return "SINGLE_ALERT", [events[-1]]

        # 3. Kiểm tra kịch bản RECONNAISSANCE_BURST:
        # Nếu có >= 2 sự kiện và TẤT CẢ các chiến thuật đều chỉ là Discovery/Reconnaissance
        is_pure_discovery = (len(all_tactics) > 0 and all_tactics.issubset(set(self.recon_tactics)))
        if is_pure_discovery:
            # Người dùng hoặc hacker chỉ đang gõ các lệnh trinh sát liên tiếp (whoami, net user, systeminfo...)
            # Không được báo sai thành Multi-Stage Attack!
            return "RECONNAISSANCE_BURST", events

        # 4. Kiểm tra kịch bản MULTI_STAGE_ATTACK:
        # Phải thỏa mãn ÍT NHẤT một trong các điều kiện Kill Chain sau:
        # - Vượt qua ít nhất 2 Chiến thuật MITRE khác nhau (ví dụ: Discovery -> Privilege Escalation)
        # - Hoặc có phả hệ cha-con (PPID == PID) kết hợp với ít nhất 1 mối đe dọa High-Risk
        # - Hoặc chuỗi sự kiện chứa các hành vi phá hoại/leo thang độc lập
        has_tactic_progression = len(all_tactics) >= 2
        high_risk_count = sum(1 for ev in events if any(t in self.high_risk_tactics for t in ev.get("mitre", {}).get("tactics", [])))

        if has_tactic_progression or (has_lineage and has_threat) or high_risk_count >= 2:
            return "MULTI_STAGE_ATTACK", events

        # 5. Nếu nhiều sự kiện nhưng không có bước tiến triển chiến thuật (ví dụ lặp lại 1 cảnh báo)
        if has_threat:
            is_critical, _ = self._is_critical_threat(events[-1])
            if is_critical:
                return "CRITICAL_SINGLE_ALERT", [events[-1]]
            return "SINGLE_ALERT", [events[-1]]

        return "SINGLE_ALERT", [events[-1]]

    def clear_session(self, session_key: str):
        """Xóa bộ nhớ đệm của riêng một session sau khi đã báo cáo xong chuỗi tấn công hoặc đợt rà quét"""
        if session_key in self.session_buckets:
            del self.session_buckets[session_key]

    def clear(self):
        """Xóa toàn bộ bộ nhớ đệm các session"""
        self.session_buckets.clear()
