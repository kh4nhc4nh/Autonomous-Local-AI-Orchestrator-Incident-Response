from typing import Dict, Any, Optional


class AlertParser:
    """
    Làm sạch, bóc tách chuyên sâu và chuẩn hóa dữ liệu Alert từ Wazuh SIEM
    Hỗ trợ:
    - Bóc tách Session ID / Logon ID để phục vụ Entity-based Correlation
    - Phân định tài khoản hệ thống (System Background) vs Phiên người dùng / Hacker
    - Phát hiện LOLBins và gắn nhãn MITRE ATT&CK tự động
    """

    MONITORED_LOLBINS = [
        "powershell", "cmd.exe", "certutil", "rundll32", "regsvr32",
        "mshta", "cscript", "wscript", "bitsadmin", "wmic", "vssadmin",
        "schtasks", "nltest", "net.exe", "net1.exe", "whoami", "curl.exe", "tar.exe"
    ]

    @staticmethod
    def parse(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        rule = raw_alert.get("rule", {})
        agent = raw_alert.get("agent", {})
        data = raw_alert.get("data", {})
        win = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
        win_data = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}
        win_sys = win.get("system", {}) if isinstance(win.get("system"), dict) else {}

        rule_id = str(rule.get("id", ""))
        rule_level = rule.get("level", 0)
        rule_desc = rule.get("description", "")
        agent_name = agent.get("name", "unknown")
        agent_ip = agent.get("ip", "unknown")
        event_id = str(win_sys.get("eventID", ""))

        # 1. Trích xuất & Bổ sung MITRE ATT&CK (Tự động gán nếu Rule gốc của Wazuh bị thiếu)
        mitre_info = rule.get("mitre", {})
        raw_ids = mitre_info.get("id", [])
        raw_tactics = mitre_info.get("tactic", [])
        mitre_ids = list(raw_ids) if isinstance(raw_ids, list) else ([raw_ids] if raw_ids else [])
        mitre_tactics = list(raw_tactics) if isinstance(raw_tactics, list) else ([raw_tactics] if raw_tactics else [])

        # Nếu Wazuh Rule chưa gán nhãn MITRE, tự động tra cứu chuẩn ATT&CK Enterprise
        if not mitre_ids:
            event_mitre_map = {
                "4720": (["T1136.001"], ["Persistence"]),                     # Create Local Account
                "4726": (["T1531"], ["Impact", "Defense Evasion"]),          # Account Access Removal
                "4732": (["T1098"], ["Persistence", "Privilege Escalation"]), # Account Manipulation (Thêm Admin)
                "4733": (["T1098"], ["Persistence", "Privilege Escalation"]), # Account Manipulation (Gỡ Admin)
                "4738": (["T1098"], ["Persistence", "Privilege Escalation"]), # Account Modification
                "4728": (["T1098"], ["Persistence"]),                         # Security Group Modified
                "4729": (["T1098"], ["Persistence"]),                         # Security Group Member Removed
                "7045": (["T1543.003"], ["Persistence", "Privilege Escalation"]), # Windows Service Creation
                "1102": (["T1070.001"], ["Defense Evasion"]),                 # Clear Security Audit Log
                "104":  (["T1070.001"], ["Defense Evasion"]),                 # Clear System Log
                "4624": (["T1021.001"], ["Lateral Movement"]) if str(win_data.get("logonType")) == "10" else (["T1078"], ["Initial Access"]),
                "4625": (["T1110"], ["Credential Access"]),                   # Password Guessing / Brute Force
                "4688": (["T1059.001"], ["Execution"])                        # Process Creation
            }
            if event_id in event_mitre_map:
                mitre_ids, mitre_tactics = event_mitre_map[event_id]
            else:
                rule_mitre_map = {
                    "60154": (["T1098"], ["Persistence", "Privilege Escalation"]),
                    "60170": (["T1098"], ["Persistence"]),
                    "60109": (["T1136.001"], ["Persistence"]),
                    "60111": (["T1531"], ["Impact"]),
                    "60122": (["T1110"], ["Credential Access"]),
                    "60204": (["T1110"], ["Credential Access"]),
                    "60104": (["T1070.001"], ["Defense Evasion"]),
                    "60101": (["T1070.001"], ["Defense Evasion"]),
                    "61138": (["T1543.003"], ["Persistence", "Privilege Escalation"]),
                    "60115": (["T1110"], ["Credential Access"]),
                    "100070": (["T1033"], ["Discovery"]),
                    "100050": (["T1071"], ["Command and Control"]),
                    "92031": (["T1087"], ["Discovery"]),
                    "92101": (["T1071"], ["Command and Control"]),
                    "92213": (["T1105"], ["Persistence", "Defense Evasion"]),
                    "92217": (["T1105"], ["Defense Evasion"]),
                    "92219": (["T1574.002"], ["Privilege Escalation", "Defense Evasion", "Persistence"])
                }
                if rule_id in rule_mitre_map:
                    mitre_ids, mitre_tactics = rule_mitre_map[rule_id]

        # 2. Trích xuất thông tin người dùng (Actor & Target User/Group) & Session ID
        # Hỗ trợ cả trường 'user' của Sysmon lẫn 'subjectUserName' của Windows Security
        subject_user = (
            win_data.get("user")
            or win_data.get("subjectUserName")
            or data.get("srcuser")
            or win_data.get("subjectAccountName")
            or ""
        )
        target_user = (
            win_data.get("targetUserName")
            or win_data.get("targetAccountName")
            or data.get("dstuser")
            or ""
        )
        member_sid = win_data.get("memberSid") or win_data.get("targetSid") or ""
        subject_domain = win_data.get("subjectDomainName", "")

        # Trích xuất Process ID (PID) và Parent Process ID (PPID) để xây dựng phả hệ tiến trình
        process_id = str(win_data.get("processId") or win_data.get("newProcessId") or "")
        parent_process_id = str(win_data.get("parentProcessId") or "")

        # Trích xuất Windows Logon ID (Session ID)
        raw_logon_id = (
            win_data.get("subjectLogonId")
            or win_data.get("targetLogonId")
            or win_data.get("logonId")
            or ""
        )
        logon_id_str = str(raw_logon_id).strip()

        # Nhận diện tài khoản hệ thống (System Background Activity)
        # Windows System services luôn sử dụng SID và Logon ID cố định: 0x3e7 (SYSTEM), 0x3e5, 0x3e4
        user_lower = subject_user.lower()
        is_system_account = (
            (user_lower in ["system", "nt authority\\system", "local service", "network service"])
            or (logon_id_str.lower() in ["0x3e7", "0x3e5", "0x3e4"])
        )

        # 3. Trích xuất Process & Command Line & Kiểm tra LOLBin
        image = (
            win_data.get("image")
            or win_data.get("newProcessName")
            or data.get("process")
            or data.get("srcfile")
            or ""
        )
        raw_cmd = (
            win_data.get("commandLine")
            or data.get("command")
            or raw_alert.get("full_log", "")
        )
        parent_image = win_data.get("parentImage") or win_data.get("parentProcessName") or ""

        # Kiểm tra sự xuất hiện của LOLBins trong Image hoặc Command Line
        cmd_full = f"{image} {raw_cmd}".lower()
        is_lolbin = any(lb in cmd_full for lb in AlertParser.MONITORED_LOLBINS)

        # Phân biệt phần mềm văn phòng/hệ thống bình thường kết nối mạng vs C2 thực sự
        benign_net_apps = ["onedrive", "dropbox", "msedge", "chrome", "firefox", "teams", "svchost", "wazuh-agent", "tiworker"]
        is_benign_net_app = any(app in image.lower() for app in benign_net_apps) and not is_lolbin

        # Tinh chỉnh Tactic cho Rule kết nối mạng (100050 / 92101):
        # Nếu là tiến trình bình thường (OneDrive, Edge, ...) thì hạ nhãn xuống Benign Network Traffic
        if rule_id in ["100050", "92101"]:
            if is_benign_net_app:
                mitre_ids = ["T1071"]
                mitre_tactics = ["Benign Network Traffic"]
            elif is_lolbin:
                mitre_ids = ["T1071"]
                mitre_tactics = ["Command and Control"]

        # 4. Trích xuất Network & Remote Context (IP Nguồn, IP Đích, Port, LogonType)
        # Hỗ trợ đầy đủ cả Windows EventLog, Sysmon và Suricata NIDS EVE JSON
        raw_src_ip = (
            win_data.get("ipAddress")
            or win_data.get("sourceIp")
            or data.get("src_ip")
            or data.get("srcip")
            or raw_alert.get("srcip")
            or ""
        )
        raw_src_port = (
            win_data.get("ipPort")
            or win_data.get("sourcePort")
            or data.get("src_port")
            or data.get("srcport")
            or ""
        )
        raw_dst_ip = (
            win_data.get("destinationIp")
            or data.get("dest_ip")
            or data.get("dstip")
            or raw_alert.get("dstip")
            or agent_ip
        )
        raw_dst_port = (
            win_data.get("destinationPort")
            or data.get("dest_port")
            or data.get("dstport")
            or ""
        )
        logon_type = str(win_data.get("logonType", ""))
        workstation = win_data.get("workstationName", "")

        # Bảng giải mã Logon Type của Windows Event ID 4624 / 4625
        logon_type_map = {
            "2": "Interactive (Trực tiếp bàn phím/console)",
            "3": "Network (Kết nối qua mạng SMB/RPC/PsExec)",
            "4": "Batch (Tác vụ nền Scheduled Task)",
            "5": "Service (Khởi chạy bởi Windows Service)",
            "7": "Unlock (Mở khóa màn hình)",
            "8": "NetworkCleartext (Truyền password dạng rõ)",
            "9": "NewCredentials (RunAs / Giả mạo credential)",
            "10": "RemoteInteractive (Đăng nhập từ xa qua RDP / Remote Desktop)",
            "11": "CachedInteractive (Đăng nhập bằng thông tin lưu đệm)"
        }
        logon_desc = logon_type_map.get(logon_type, f"LogonType {logon_type}" if logon_type else "")

        # Định hình Protocol và Port (Kèm hỗ trợ giao thức mạng từ Suricata)
        net_proto = str(data.get("proto", "")).upper()
        if net_proto:
            protocol = f"{net_proto} (Network Packet)"
        else:
            protocol = "Local Console / System"

        if logon_type == "10":
            protocol = "RDP (Remote Desktop)"
            if not raw_dst_port:
                raw_dst_port = "3389"
        elif logon_type == "3":
            protocol = "SMB / RPC (Network Share)"
            if not raw_dst_port:
                raw_dst_port = "445"
        elif str(raw_dst_port) == "22" or str(raw_src_port) == "22":
            protocol = "SSH Remote Shell"

        # Chuẩn hóa chuỗi hiển thị Nguồn (Source) và Đích (Destination)
        if raw_src_ip in ["-", "::1", "127.0.0.1", ""] or not raw_src_ip:
            source_display = f"Local Console ({subject_user or 'Local User'})"
            source_ip = "127.0.0.1 (Local)"
        else:
            source_ip = raw_src_ip
            source_display = f"{raw_src_ip}:{raw_src_port}" if raw_src_port else raw_src_ip

        dest_ip = raw_dst_ip or agent_ip
        dest_display = f"{agent_name} ({dest_ip}:{raw_dst_port})" if raw_dst_port else f"{agent_name} ({dest_ip})"

        # 5. Xây dựng Định danh Phiên / Thực thể duy nhất (Entity-Based Session Key)
        # Ngăn chặn hoàn toàn việc log nền hệ thống SYSTEM bị gom chung với phiên của Hacker
        if logon_id_str and logon_id_str not in ["0x0", "-", ""]:
            if is_system_account:
                session_key = f"{agent_name}:system:{logon_id_str}"
            else:
                actor_id = subject_user or "actor"
                session_key = f"{agent_name}:session:{actor_id}_{logon_id_str}"
        elif raw_src_ip and raw_src_ip not in ["-", "::1", "127.0.0.1", ""]:
            session_key = f"{agent_name}:net:{raw_src_ip}"
        elif subject_user and not is_system_account:
            session_key = f"{agent_name}:user:{subject_user}"
        else:
            session_key = f"{agent_name}:system_bg" if is_system_account else f"{agent_name}:host_general"

        # 6. Xây dựng diễn giải hành vi cụ thể (Action Detail / Command)
        action_detail = ""
        suri_alert = data.get("alert", {}) if isinstance(data.get("alert"), dict) else {}
        suri_sig = suri_alert.get("signature") or data.get("signature") or ""
        suri_cat = suri_alert.get("category") or data.get("category") or ""

        if suri_sig:
            action_detail = f"Phát hiện xâm nhập mạng [Suricata]: {suri_sig} (Phân loại: {suri_cat or 'NIDS Event'})"
            if not mitre_ids:
                mitre_ids = ["T1190"]
            if not mitre_tactics:
                mitre_tactics = ["Initial Access", "Command and Control"]
        elif raw_cmd and raw_cmd.strip() and raw_cmd.strip().lower() != rule_desc.lower():
            action_detail = f"Thực thi lệnh: {raw_cmd.strip()}"
        elif event_id == "4720":
            action_detail = f"Tạo tài khoản mới: [{target_user}] bởi User [{subject_user}]"
        elif event_id == "4726":
            action_detail = f"Xóa tài khoản: [{target_user}] bởi User [{subject_user}]"
        elif event_id == "4738":
            action_detail = f"Thay đổi thuộc tính tài khoản: [{target_user}] bởi User [{subject_user}]"
        elif event_id == "4732":
            detail_target = target_user if target_user else "Administrators"
            action_detail = f"THÊM tài khoản (SID: {member_sid}) vào nhóm đặc quyền [{detail_target}] bởi User [{subject_user}]"
        elif event_id == "4733":
            detail_target = target_user if target_user else "Administrators"
            action_detail = f"GỠ tài khoản khỏi nhóm đặc quyền [{detail_target}] bởi User [{subject_user}]"
        elif event_id == "4728":
            action_detail = f"Thêm thành viên vào Security Group [{target_user}] bởi User [{subject_user}]"
        elif event_id == "4729":
            action_detail = f"Gỡ thành viên khỏi Security Group [{target_user}] bởi User [{subject_user}]"
        elif event_id == "7045":
            svc_name = win_data.get("serviceName", "Unknown")
            svc_bin = win_data.get("imagePath", "Unknown")
            action_detail = f"Cài đặt Windows Service ngầm mới: [{svc_name}] -> Binary: [{svc_bin}]"
        elif event_id == "4624":
            action_detail = f"Đăng nhập THÀNH CÔNG tài khoản [{target_user}] qua {logon_desc} từ IP [{source_ip}] (Máy: {workstation or 'N/A'})"
        elif event_id == "4625":
            action_detail = f"Đăng nhập THẤT BẠI tài khoản [{target_user}] (Sai mật khẩu/User không tồn tại) qua {logon_desc} từ IP [{source_ip}]"
        elif event_id in ["1102", "104"]:
            channel = win_sys.get("channel", "Security/System")
            action_detail = f"XÓA SẠCH toàn bộ Audit Event Log ({channel}) bởi User [{subject_user}] (Tẩu thoát/Cover Tracks)"
        elif rule_id == "100050":
            action_detail = f"Tiến trình [{image or 'N/A'}] kết nối mạng tới [{dest_ip}:{raw_dst_port or 'N/A'}]"
        elif rule_id == "92219":
            action_detail = f"Phát hiện dấu hiệu DLL Search Order Hijacking: [{image or raw_cmd or rule_desc}]"
        elif rule_id == "92213":
            action_detail = f"Phát hiện file thực thi thả vào thư mục mã độc: [{image or raw_cmd or rule_desc}]"
        elif rule_id == "92217":
            action_detail = f"Phát hiện file thực thi thả vào Windows root: [{image or raw_cmd or rule_desc}]"
        else:
            sys_msg = win_sys.get("message", "")
            if sys_msg:
                first_line = sys_msg.splitlines()[0].strip().strip('"')
                action_detail = f"{first_line} (Actor: {subject_user or 'N/A'}, Target: {target_user or 'N/A'})"
            else:
                action_detail = rule_desc

        clean_alert = {
            "timestamp": raw_alert.get("timestamp", ""),
            "agent": f"{agent_name} ({agent_ip})",
            "session_id": logon_id_str or "N/A",
            "session_key": session_key,
            "is_system_account": is_system_account,
            "rule_id": rule_id,
            "rule_level": rule_level,
            "rule_description": rule_desc,
            "event_id": event_id,
            "actor_user": subject_user or "N/A",
            "target_user": target_user or "N/A",
            "action_detail": action_detail,
            "network": {
                "source": source_display,
                "destination": dest_display,
                "src_ip": source_ip,
                "src_port": raw_src_port or "N/A",
                "dst_ip": dest_ip,
                "dst_port": raw_dst_port or "N/A",
                "protocol": protocol,
                "logon_type": logon_desc
            },
            "process": {
                "pid": process_id or "N/A",
                "ppid": parent_process_id or "N/A",
                "image": image or "N/A",
                "command_line": raw_cmd or action_detail,
                "parent_image": parent_image or "N/A",
                "is_lolbin": is_lolbin
            },
            "mitre": {
                "ids": mitre_ids,
                "tactics": mitre_tactics
            }
        }

        return clean_alert
