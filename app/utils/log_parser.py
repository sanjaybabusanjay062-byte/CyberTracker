import os
import re
import csv
import json
from datetime import datetime, date

# Regular expressions for text log parsing
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
SYSLOG_REGEX = re.compile(
    r'^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>[^\s:]+)\s+(?P<service>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
)
ISO_TIMESTAMP_REGEX = re.compile(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b')


def detect_format(file_path):
    """Auto-detect format of log file (csv, json, txt)."""
    ext = os.path.splitext(file_path)[1].lower().replace('.', '')
    if ext in ['csv', 'json', 'txt', 'log']:
        # Confirm by checking content
        if ext == 'json':
            return 'json'
        if ext == 'csv':
            return 'csv'
        return 'txt'

    # Fallback inspection
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in range(10):
                line = f.readline().strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') or line.startswith('{'):
                    return 'json'
                if ',' in line and ('timestamp' in line.lower() or 'source' in line.lower() or 'ip' in line.lower()):
                    return 'csv'
                return 'txt'
    except Exception:
        pass
    return 'txt'


def _parse_timestamp(val):
    """Safely parse various datetime strings into a Python datetime object."""
    if not val:
        return datetime.utcnow()
    if isinstance(val, datetime):
        return val

    val_str = str(val).strip().strip('"').strip("'")

    # Common formats
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y/%m/%d %H:%M:%S',
        '%d/%m/%Y %H:%M:%S',
        '%b %d %H:%M:%S',
        '%b %d %Y %H:%M:%S'
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(val_str, fmt)
            # If syslog without year, assign current or recent year
            if dt.year == 1900:
                current_year = date.today().year
                dt = dt.replace(year=current_year)
            return dt
        except ValueError:
            continue

    # Try regex ISO match
    iso_match = ISO_TIMESTAMP_REGEX.search(val_str)
    if iso_match:
        clean_iso = iso_match.group(0).replace('T', ' ').replace('Z', '')
        try:
            return datetime.strptime(clean_iso[:19], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass

    return datetime.utcnow()


def classify_event(record):
    """Classify event into standard types and severity levels.
    Types: login_success, login_failure, file_access, process_exec, network_conn, data_transfer, privilege_escalation.
    Severities: info, low, medium, high, critical.
    """
    desc = str(record.get('event_description', '') or '').lower()
    raw = str(record.get('raw_log', '') or '').lower()
    etype = str(record.get('event_type', '') or '').lower()
    status = str(record.get('status', '') or '').lower()
    text = f"{desc} {raw} {etype} {status}"

    # Suspicious flags
    is_suspicious = False
    threat_cat = None

    # 1. Base64 encoded or malicious shell execution
    if any(k in text for k in ['base64', 'encodedcommand', 'mimikatz', 'netcat', 'nc -e', '/bin/sh -i', 'nmap']):
        return 'process_exec', 'critical', True, 'Malicious Command / Encoded Execution'

    # 2. Sensitive file access
    if any(k in text for k in ['/etc/shadow', '/etc/passwd', 'sam', 'system32/config/sam', 'authorized_keys']):
        return 'file_access', 'critical', True, 'Sensitive Credential File Access'

    # 3. Privilege escalation
    if any(k in text for k in ['sudo', 'privilege escalation', 'wheel', 'uid=0', 'runas', 'setuid']):
        return 'privilege_escalation', 'high', True, 'Privilege Escalation Activity'

    # 4. Data exfiltration / Large transfer
    if any(k in text for k in ['exfiltrat', 'large transfer', 'tar -czf', 'scp -r', 'rsync', 'curl -x post', 'external mount']):
        return 'data_transfer', 'high', True, 'Potential Data Exfiltration'

    # 5. Failed authentication / Brute force indicators
    if any(k in text for k in ['failed', 'invalid user', 'auth failure', 'failure', 'password rejected', 'denied']):
        if 'root' in text or 'admin' in text:
            return 'login_failure', 'high', True, 'Privileged Login Failure'
        return 'login_failure', 'medium', False, 'Authentication Failure'

    # 6. Successful authentication
    if any(k in text for k in ['accepted password', 'logged on', 'login success', 'success', 'session opened']):
        # Off-hours or unusual can be classified during threat analysis
        return 'login_success', 'info', False, None

    # 7. Network / Firewall block
    if any(k in text for k in ['[ufw block]', 'firewall drop', 'port scan', 'syn scan', 'connection dropped', 'blocked']):
        return 'network_conn', 'medium', True, 'Network Probe / Blocked Traffic'

    # 8. Network connection
    if any(k in text for k in ['network', 'connected to', 'traffic', 'tcp', 'udp', 'established']):
        return 'network_conn', 'low', False, None

    # 9. Generic file operations
    if any(k in text for k in ['file', 'read', 'write', 'deleted', 'created', 'modified']):
        return 'file_access', 'low', False, None

    # 10. General process execution
    if any(k in text for k in ['process', 'spawned', 'started service', 'exec']):
        return 'process_exec', 'low', False, None

    return etype or 'system_event', 'info', False, None


def normalize_record(raw_record, source_format='generic'):
    """Normalize arbitrary extracted data to the standard LogRecord schema."""
    # Find matching timestamp
    dt = _parse_timestamp(raw_record.get('timestamp'))

    # IP resolution
    src_ip = raw_record.get('source_ip') or raw_record.get('src_ip') or raw_record.get('ip')
    dest_ip = raw_record.get('destination_ip') or raw_record.get('dest_ip') or raw_record.get('dst_ip')

    # Username resolution
    username = raw_record.get('username') or raw_record.get('user') or raw_record.get('account')

    # Description
    desc = raw_record.get('event_description') or raw_record.get('description') or raw_record.get('message') or ''
    raw_log = raw_record.get('raw_log') or str(raw_record)

    # Classify event
    ev_type, severity, is_suspicious, threat_category = classify_event({
        'event_description': desc,
        'raw_log': raw_log,
        'event_type': raw_record.get('event_type'),
        'status': raw_record.get('status')
    })

    # Override severity if raw_record provides explicit severity
    explicit_sev = raw_record.get('severity')
    if explicit_sev and explicit_sev.lower() in ['info', 'low', 'medium', 'high', 'critical']:
        severity = explicit_sev.lower()

    return {
        'timestamp': dt,
        'source_ip': str(src_ip).strip() if src_ip else None,
        'destination_ip': str(dest_ip).strip() if dest_ip else None,
        'username': str(username).strip() if username else None,
        'event_type': ev_type,
        'event_description': str(desc).strip() or f"{ev_type} event",
        'severity': severity,
        'raw_log': str(raw_log),
        'is_suspicious': is_suspicious,
        'threat_category': threat_category
    }


def parse_csv_log(file_path):
    """Parse CSV log file with auto-detected columns and comments support."""
    records = []
    if not os.path.exists(file_path):
        return records

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        # Read lines, filtering comments
        lines = [line for line in f if not line.strip().startswith('#') and line.strip()]

    if not lines:
        return records

    reader = csv.DictReader(lines)
    # Normalize field names to lower case without spaces
    if not reader.fieldnames:
        return records

    field_map = {fn: fn.strip().lower().replace(' ', '_') for fn in reader.fieldnames}

    for row in reader:
        norm_row = {}
        for orig_key, val in row.items():
            if orig_key is None:
                continue
            k = field_map.get(orig_key, orig_key.lower())
            norm_row[k] = val

        # Search for canonical keys
        extracted = {}
        extracted['timestamp'] = norm_row.get('timestamp') or norm_row.get('time') or norm_row.get('datetime') or norm_row.get('date')
        extracted['source_ip'] = norm_row.get('source_ip') or norm_row.get('src_ip') or norm_row.get('ip') or norm_row.get('client_ip')
        extracted['destination_ip'] = norm_row.get('destination_ip') or norm_row.get('dest_ip') or norm_row.get('dst_ip')
        extracted['username'] = norm_row.get('username') or norm_row.get('user') or norm_row.get('account')
        extracted['event_type'] = norm_row.get('event_type') or norm_row.get('action') or norm_row.get('event')
        extracted['status'] = norm_row.get('status') or norm_row.get('result') or norm_row.get('outcome')
        extracted['severity'] = norm_row.get('severity') or norm_row.get('level')
        extracted['event_description'] = norm_row.get('description') or norm_row.get('message') or norm_row.get('event_description') or f"Action: {extracted.get('event_type')}, Status: {extracted.get('status')}"
        extracted['raw_log'] = json.dumps(row)

        records.append(normalize_record(extracted, source_format='csv'))

    return records


def parse_json_log(file_path):
    """Parse JSON log file (JSON array or newline-delimited JSON lines)."""
    records = []
    if not os.path.exists(file_path):
        return records

    content = ""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        # Filter lines starting with #
        lines = [l for l in f if not l.strip().startswith('#')]
        content = "".join(lines).strip()

    if not content:
        return records

    # Attempt standard JSON parse
    data = None
    try:
        data = json.loads(content)
    except Exception:
        # Try JSON Lines
        data = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    data.append(json.loads(line))
                except Exception:
                    pass

    if not data:
        return records

    if isinstance(data, dict):
        data = [data]

    for item in data:
        if not isinstance(item, dict):
            continue

        extracted = {
            'timestamp': item.get('timestamp') or item.get('time') or item.get('@timestamp'),
            'source_ip': item.get('source_ip') or item.get('src_ip') or item.get('ip') or item.get('host'),
            'destination_ip': item.get('destination_ip') or item.get('dest_ip') or item.get('dst_ip') or item.get('target'),
            'username': item.get('username') or item.get('user') or item.get('account'),
            'event_type': item.get('event_type') or item.get('event') or item.get('action'),
            'severity': item.get('severity') or item.get('level'),
            'status': item.get('status'),
            'event_description': item.get('description') or item.get('message') or item.get('event') or item.get('process'),
            'raw_log': json.dumps(item)
        }

        # Handle process/host specific fields
        if item.get('process') and not extracted['event_description']:
            extracted['event_description'] = f"Process {item.get('process')} (PID: {item.get('pid', 'N/A')})"
        elif item.get('process') and extracted['event_description']:
            extracted['event_description'] = f"{extracted['event_description']} - Process: {item.get('process')}"

        records.append(normalize_record(extracted, source_format='json'))

    return records


def parse_txt_log(file_path):
    """Parse plain text, syslog, or firewall logs."""
    records = []
    if not os.path.exists(file_path):
        return records

    current_year = date.today().year

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            raw_line = line.strip()
            if not raw_line or raw_line.startswith('#'):
                continue

            extracted = {
                'timestamp': None,
                'source_ip': None,
                'destination_ip': None,
                'username': None,
                'event_type': 'system_event',
                'event_description': raw_line,
                'severity': 'info',
                'raw_log': raw_line
            }

            # Check Syslog Regex
            syslog_match = SYSLOG_REGEX.match(raw_line)
            if syslog_match:
                m_dict = syslog_match.groupdict()
                month_str = m_dict['month']
                day_str = m_dict['day']
                time_str = m_dict['time']
                try:
                    ts_str = f"{month_str} {day_str} {time_str} {current_year}"
                    extracted['timestamp'] = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
                except Exception:
                    extracted['timestamp'] = datetime.utcnow()

                extracted['event_description'] = f"[{m_dict['service']}] {m_dict['message']}"

            # Check for ISO timestamp
            iso_match = ISO_TIMESTAMP_REGEX.search(raw_line)
            if iso_match and not extracted['timestamp']:
                extracted['timestamp'] = _parse_timestamp(iso_match.group(0))

            # Extract IP addresses
            ips = IPV4_REGEX.findall(raw_line)
            # Check for SRC= / DST= patterns in firewall logs
            src_match = re.search(r'SRC=([0-9\.]+)', raw_line, re.IGNORECASE)
            dst_match = re.search(r'DST=([0-9\.]+)', raw_line, re.IGNORECASE)

            if src_match:
                extracted['source_ip'] = src_match.group(1)
            elif ips:
                extracted['source_ip'] = ips[0]

            if dst_match:
                extracted['destination_ip'] = dst_match.group(1)
            elif len(ips) > 1 and ips[1] != extracted['source_ip']:
                extracted['destination_ip'] = ips[1]

            # Extract user mentions
            user_match = re.search(r'(?:user|for user|account|Account Name:)\s+([a-zA-Z0-9_\-\.]+)', raw_line, re.IGNORECASE)
            if user_match:
                extracted['username'] = user_match.group(1)

            records.append(normalize_record(extracted, source_format='txt'))

    return records


def parse_log_file(file_path):
    """High-level dispatcher to detect format and return list of normalized records."""
    fmt = detect_format(file_path)
    if fmt == 'csv':
        return parse_csv_log(file_path)
    elif fmt == 'json':
        return parse_json_log(file_path)
    else:
        return parse_txt_log(file_path)
