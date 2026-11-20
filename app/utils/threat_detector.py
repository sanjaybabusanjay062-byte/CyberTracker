import uuid
from datetime import datetime, timedelta
from collections import defaultdict


def _get_timestamp(record):
    """Safely obtain datetime from record object or dict."""
    ts = getattr(record, 'timestamp', None)
    if ts is None and isinstance(record, dict):
        ts = record.get('timestamp')
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace('Z', ''))
        except Exception:
            return datetime.utcnow()
    return ts or datetime.utcnow()


def _get_field(record, field_name, default=None):
    """Safely extract field from object or dict."""
    if hasattr(record, field_name):
        val = getattr(record, field_name)
        if val is not None:
            return val
    if isinstance(record, dict):
        return record.get(field_name, default)
    return default


def detect_brute_force(log_records):
    """Detect 5+ failed logins within 5 minutes from same IP."""
    alerts = []
    ip_records = defaultdict(list)

    for rec in log_records:
        etype = str(_get_field(rec, 'event_type', '')).lower()
        desc = str(_get_field(rec, 'event_description', '')).lower()
        src_ip = _get_field(rec, 'source_ip')

        if (etype == 'login_failure' or 'fail' in desc or 'invalid user' in desc) and src_ip:
            ip_records[src_ip].append(rec)

    for src_ip, records in ip_records.items():
        records.sort(key=_get_timestamp)
        n = len(records)
        i = 0
        while i < n:
            window_start_time = _get_timestamp(records[i])
            window_end_time = window_start_time + timedelta(minutes=5)
            window_records = [r for r in records if window_start_time <= _get_timestamp(r) <= window_end_time]

            if len(window_records) >= 5:
                count = len(window_records)
                usernames = list({_get_field(r, 'username') for r in window_records if _get_field(r, 'username')})
                user_str = f" targeting user(s): {', '.join(usernames)}" if usernames else ""
                severity = 'critical' if count >= 10 else 'high'

                alerts.append({
                    'alert_type': 'Brute Force Attack',
                    'severity': severity,
                    'description': f"Detected {count} failed authentication attempts within 5 minutes from IP {src_ip}{user_str}.",
                    'source_ip': src_ip,
                    'username': usernames[0] if usernames else None,
                    'timestamp': window_start_time,
                    'evidence': f"Failed attempts count: {count}"
                })
                # Skip past this burst window
                i += count
            else:
                i += 1

    return alerts


def detect_off_hours_access(log_records):
    """Detect successful logins occurring between 11:00 PM (23:00) and 6:00 AM (06:00)."""
    alerts = []
    for rec in log_records:
        etype = str(_get_field(rec, 'event_type', '')).lower()
        desc = str(_get_field(rec, 'event_description', '')).lower()

        if etype == 'login_success' or 'accepted' in desc or 'logged on' in desc:
            ts = _get_timestamp(rec)
            hour = ts.hour
            if hour >= 23 or hour < 6:
                src_ip = _get_field(rec, 'source_ip')
                user = _get_field(rec, 'username') or 'Unknown User'

                alerts.append({
                    'alert_type': 'Off-Hours Access',
                    'severity': 'medium',
                    'description': f"User '{user}' authenticated successfully during off-hours at {ts.strftime('%H:%M:%S')} from {src_ip or 'unspecified IP'}.",
                    'source_ip': src_ip,
                    'username': user,
                    'timestamp': ts,
                    'evidence': f"Login event outside 06:00-23:00 standard operational window"
                })
    return alerts


def detect_unusual_ip(log_records, known_ips=None):
    """Detect logins or activity from unknown or public external IPs."""
    if known_ips is None:
        # Default internal network ranges & approved admin hosts
        known_ips = {'127.0.0.1', 'localhost', '10.0.0.15', '10.0.0.20', '192.168.1.100'}

    alerts = []
    flagged_ips = set()

    for rec in log_records:
        src_ip = _get_field(rec, 'source_ip')
        etype = str(_get_field(rec, 'event_type', '')).lower()
        user = _get_field(rec, 'username')

        if not src_ip or src_ip in known_ips or src_ip.startswith('127.') or src_ip.startswith('10.'):
            continue

        # Look for successful logins or sensitive operations from anomalous IP
        if (etype == 'login_success' or 'login' in etype) and src_ip not in flagged_ips:
            flagged_ips.add(src_ip)
            alerts.append({
                'alert_type': 'Unusual IP Access',
                'severity': 'high',
                'description': f"Authentication detected from unrecognized external IP address {src_ip} for account '{user or 'unknown'}'.",
                'source_ip': src_ip,
                'username': user,
                'timestamp': _get_timestamp(rec),
                'evidence': f"Origin IP {src_ip} not in known baseline corporate infrastructure"
            })
    return alerts


def detect_privilege_escalation(log_records):
    """Detect privilege escalation, sudo, root or credential file access."""
    alerts = []
    for rec in log_records:
        etype = str(_get_field(rec, 'event_type', '')).lower()
        desc = str(_get_field(rec, 'event_description', '')).lower()
        raw = str(_get_field(rec, 'raw_log', '')).lower()
        combined = f"{desc} {raw} {etype}"

        is_priv = False
        reason = ""

        if any(f in combined for f in ['/etc/shadow', '/etc/passwd', 'sam registry', 'mimikatz']):
            is_priv = True
            reason = "Unauthorized read/access to sensitive credential store"
        elif 'sudo' in combined and ('root' in combined or 'wheel' in combined or 'nopasswd' in combined):
            is_priv = True
            reason = "Privileged execution or sudo escalation detected"
        elif etype == 'privilege_escalation':
            is_priv = True
            reason = desc or "Privilege escalation activity detected"

        if is_priv:
            alerts.append({
                'alert_type': 'Privilege Escalation',
                'severity': 'critical',
                'description': f"{reason}: {_get_field(rec, 'event_description')}",
                'source_ip': _get_field(rec, 'source_ip'),
                'username': _get_field(rec, 'username'),
                'timestamp': _get_timestamp(rec),
                'evidence': _get_field(rec, 'raw_log') or desc
            })
    return alerts


def detect_data_exfil(log_records):
    """Detect large file transfers, archives, or high-volume file accesses indicating exfiltration."""
    alerts = []
    user_file_access = defaultdict(list)

    for rec in log_records:
        etype = str(_get_field(rec, 'event_type', '')).lower()
        desc = str(_get_field(rec, 'event_description', '')).lower()
        raw = str(_get_field(rec, 'raw_log', '')).lower()
        combined = f"{desc} {raw} {etype}"

        # Direct exfil patterns
        if any(term in combined for term in ['exfiltration', 'large transfer', 'tar -czf', 'scp -r', 'rsync', 'external mount', 'copy to external']):
            alerts.append({
                'alert_type': 'Data Exfiltration',
                'severity': 'critical',
                'description': f"Data staging or external exfiltration pattern identified: {_get_field(rec, 'event_description')}",
                'source_ip': _get_field(rec, 'source_ip'),
                'username': _get_field(rec, 'username'),
                'timestamp': _get_timestamp(rec),
                'evidence': _get_field(rec, 'raw_log') or desc
            })

        # Track multiple file access events
        if etype == 'file_access' and _get_field(rec, 'username'):
            user_file_access[_get_field(rec, 'username')].append(rec)

    # Detect rapid file harvesting (> 8 files in 10 minutes)
    for user, records in user_file_access.items():
        if len(records) >= 8:
            records.sort(key=_get_timestamp)
            first_ts = _get_timestamp(records[0])
            last_ts = _get_timestamp(records[-1])
            if (last_ts - first_ts) <= timedelta(minutes=15):
                alerts.append({
                    'alert_type': 'Data Exfiltration',
                    'severity': 'high',
                    'description': f"Rapid file access cluster: User '{user}' accessed {len(records)} files in short succession.",
                    'source_ip': _get_field(records[0], 'source_ip'),
                    'username': user,
                    'timestamp': first_ts,
                    'evidence': f"High frequency file reading burst ({len(records)} files in < 15m)"
                })

    return alerts


def detect_lateral_movement(log_records):
    """Detect the same user accessing multiple target systems/devices."""
    alerts = []
    user_targets = defaultdict(lambda: defaultdict(list))

    for rec in log_records:
        user = _get_field(rec, 'username')
        dest_ip = _get_field(rec, 'destination_ip')
        src_ip = _get_field(rec, 'source_ip')

        if user and dest_ip and dest_ip != src_ip:
            user_targets[user][dest_ip].append(rec)

    for user, targets_map in user_targets.items():
        if len(targets_map) >= 3:
            target_list = list(targets_map.keys())
            first_rec = list(targets_map.values())[0][0]
            alerts.append({
                'alert_type': 'Lateral Movement',
                'severity': 'high',
                'description': f"Account '{user}' accessed {len(target_list)} distinct target hosts ({', '.join(target_list[:4])}) suggesting lateral movement across the network.",
                'source_ip': _get_field(first_rec, 'source_ip'),
                'username': user,
                'timestamp': _get_timestamp(first_rec),
                'evidence': f"Connections to {len(target_list)} disparate endpoints: {', '.join(target_list)}"
            })
    return alerts


def detect_suspicious_process(log_records):
    """Detect malicious process executions, encoded commands, or offensive tools."""
    alerts = []
    suspicious_patterns = [
        ('base64', 'Base64 encoded CLI command execution'),
        ('-enc', 'PowerShell encoded command execution'),
        ('encodedcommand', 'PowerShell encoded command execution'),
        ('mimikatz', 'Credential dumping tool execution (Mimikatz)'),
        ('nc -e', 'Netcat reverse shell spawned'),
        ('netcat', 'Suspicious Netcat invocation'),
        ('nmap', 'Network scanning / port discovery tool executed'),
        ('certutil -urlcache', 'Certutil payload download stager'),
        ('/bin/sh -i', 'Interactive shell spawned from non-interactive process')
    ]

    for rec in log_records:
        desc = str(_get_field(rec, 'event_description', '')).lower()
        raw = str(_get_field(rec, 'raw_log', '')).lower()
        combined = f"{desc} {raw}"

        for pattern, label in suspicious_patterns:
            if pattern in combined:
                alerts.append({
                    'alert_type': 'Suspicious Process Execution',
                    'severity': 'critical',
                    'description': f"{label}: {_get_field(rec, 'event_description')}",
                    'source_ip': _get_field(rec, 'source_ip'),
                    'username': _get_field(rec, 'username'),
                    'timestamp': _get_timestamp(rec),
                    'evidence': _get_field(rec, 'raw_log') or desc
                })
                break
    return alerts


def run_all_detections(log_records, case_id=None):
    """Run all threat detection heuristics and return unified alerts."""
    all_alerts = []
    all_alerts.extend(detect_brute_force(log_records))
    all_alerts.extend(detect_off_hours_access(log_records))
    all_alerts.extend(detect_unusual_ip(log_records))
    all_alerts.extend(detect_privilege_escalation(log_records))
    all_alerts.extend(detect_data_exfil(log_records))
    all_alerts.extend(detect_lateral_movement(log_records))
    all_alerts.extend(detect_suspicious_process(log_records))

    # Add unique alert_id and format
    formatted_alerts = []
    for a in all_alerts:
        formatted_alerts.append({
            'alert_id': f"ALT-{uuid.uuid4().hex[:8].upper()}",
            'alert_type': a['alert_type'],
            'severity': a['severity'],
            'description': a['description'],
            'source_ip': a.get('source_ip'),
            'username': a.get('username'),
            'timestamp': a.get('timestamp') or datetime.utcnow(),
            'evidence': a.get('evidence', '')
        })

    # Sort alerts by timestamp descending
    formatted_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
    return formatted_alerts
