"""
CYBERTRACE AI — Database Initialization Script
Creates all tables and seeds realistic fictional sample data for demonstration.
NOTE: ALL data in this file is SIMULATED DATA FOR DEMONSTRATION PURPOSES ONLY.
"""
import os
import sys
from datetime import datetime, timedelta
import random

# Ensure the app can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User, Case, Evidence, LogRecord, ThreatAlert, AuditLog, CaseNote
from app.utils.hashing import hash_password

app = create_app()

# ── SIMULATED DATA CONSTANTS ──────────────────────────────────────────────────
SAMPLE_IPS_NORMAL = [
    '10.0.0.5', '10.0.0.12', '10.0.0.23', '10.0.1.100',
    '192.168.1.15', '192.168.1.44', '172.16.0.8', '172.16.0.33'
]
SUSPICIOUS_IP_1 = '203.0.113.42'   # Brute force origin
SUSPICIOUS_IP_2 = '198.51.100.77'  # Unusual access IP

SAMPLE_USERS_LOGS = [
    'jsmith', 'mdavis', 'rjohnson', 'admin_user', 'lstewart',
    'bwilson', 'tharris', 'kmartin', 'jsmith', 'admin_user'
]


def create_sample_files():
    """Create the sample data directory and CSV/JSON/TXT files with recent timestamps."""
    os.makedirs('sample_data', exist_ok=True)

    # Dynamic base date: yesterday
    base = datetime.utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(days=1)
    day_str = base.strftime('%Y-%m-%d')
    next_day_str = (base + timedelta(days=1)).strftime('%Y-%m-%d')
    mon_day = base.strftime('%b %d')

    # --- Sample Auth Log CSV ---
    csv_path = 'sample_data/sample_auth_logs.csv'
    with open(csv_path, 'w') as f:
        f.write('# SIMULATED DATA - For demonstration purposes only\n')
        f.write('timestamp,source_ip,username,event_type,status,user_agent,session_id\n')
        rows = [
            # Normal business hours logins
            (f'{day_str} 08:02:14', '10.0.0.5',    'jsmith',      'login', 'success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-001'),
            (f'{day_str} 08:15:33', '10.0.0.12',   'mdavis',      'login', 'success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-002'),
            (f'{day_str} 08:34:51', '192.168.1.15','admin_user',  'login', 'success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-003'),
            (f'{day_str} 09:12:04', '10.0.0.23',   'rjohnson',    'login', 'success', 'Mozilla/5.0 (Macintosh)',       'sess-004'),
            (f'{day_str} 09:45:22', '172.16.0.8',  'lstewart',    'login', 'success', 'Mozilla/5.0 (Linux)',           'sess-005'),
            (f'{day_str} 10:01:09', '10.0.1.100',  'bwilson',     'login', 'success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-006'),
            (f'{day_str} 11:22:17', '10.0.0.5',    'jsmith',      'login', 'success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-007'),
            (f'{day_str} 13:04:55', '10.0.0.12',   'mdavis',      'login', 'success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-008'),
            # Brute force from 203.0.113.42 at 02:15 AM
            (f'{day_str} 02:15:03', SUSPICIOUS_IP_1, 'admin',     'login', 'failed',  'python-requests/2.28', 'sess-fail-01'),
            (f'{day_str} 02:15:14', SUSPICIOUS_IP_1, 'admin',     'login', 'failed',  'python-requests/2.28', 'sess-fail-02'),
            (f'{day_str} 02:15:22', SUSPICIOUS_IP_1, 'root',      'login', 'failed',  'python-requests/2.28', 'sess-fail-03'),
            (f'{day_str} 02:15:33', SUSPICIOUS_IP_1, 'root',      'login', 'failed',  'python-requests/2.28', 'sess-fail-04'),
            (f'{day_str} 02:15:41', SUSPICIOUS_IP_1, 'admin',     'login', 'failed',  'python-requests/2.28', 'sess-fail-05'),
            (f'{day_str} 02:15:52', SUSPICIOUS_IP_1, 'jsmith',    'login', 'failed',  'python-requests/2.28', 'sess-fail-06'),
            (f'{day_str} 02:16:04', SUSPICIOUS_IP_1, 'mdavis',    'login', 'failed',  'python-requests/2.28', 'sess-fail-07'),
            (f'{day_str} 02:16:11', SUSPICIOUS_IP_1, 'lstewart',  'login', 'failed',  'python-requests/2.28', 'sess-fail-08'),
            (f'{day_str} 02:16:23', SUSPICIOUS_IP_1, 'admin_user','login', 'failed',  'python-requests/2.28', 'sess-fail-09'),
            (f'{day_str} 02:16:35', SUSPICIOUS_IP_1, 'sysadmin',  'login', 'failed',  'python-requests/2.28', 'sess-fail-10'),
            (f'{day_str} 02:16:47', SUSPICIOUS_IP_1, 'operator',  'login', 'failed',  'python-requests/2.28', 'sess-fail-11'),
            # Successful off-hours login from unusual IP
            (f'{day_str} 03:22:19', SUSPICIOUS_IP_2, 'jsmith',    'login', 'success', 'curl/7.84.0',          'sess-sus-01'),
            # Normal afternoon activity
            (f'{day_str} 14:12:08', '10.0.0.5',    'jsmith',      'login', 'success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-009'),
            (f'{day_str} 14:35:40', '10.0.0.23',   'rjohnson',    'login', 'success', 'Mozilla/5.0 (Macintosh)',       'sess-010'),
            (f'{day_str} 15:08:27', '192.168.1.15','admin_user',  'login', 'success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-011'),
            (f'{day_str} 16:22:51', '10.0.0.12',   'mdavis',      'logout','success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-002'),
            (f'{day_str} 16:45:03', '10.0.0.5',    'jsmith',      'logout','success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-009'),
            (f'{day_str} 17:01:19', '192.168.1.15','admin_user',  'logout','success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-011'),
            (f'{next_day_str} 08:11:04', '10.0.0.5',    'jsmith',      'login', 'success', 'Mozilla/5.0 (Windows NT 10.0)', 'sess-012'),
            (f'{next_day_str} 08:28:33', '172.16.0.33',  'kmartin',    'login', 'success', 'Mozilla/5.0 (Linux)',           'sess-013'),
        ]
        for row in rows:
            f.write(','.join(str(r) for r in row) + '\n')

    # --- Sample System Events JSON ---
    json_path = 'sample_data/sample_system_events.json'
    with open(json_path, 'w') as f:
        import json
        events = [
            {"timestamp": f"{day_str}T02:17:05Z", "host": "srv-prod-01", "process": "sshd",         "pid": 4821, "event": "Session opened for user jsmith",             "user": "jsmith",      "severity": "info",     "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T02:19:33Z", "host": "srv-prod-01", "process": "sudo",          "pid": 4833, "event": "User jsmith ran: sudo -l",                   "user": "jsmith",      "severity": "medium",   "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T02:21:14Z", "host": "srv-prod-01", "process": "sudo",          "pid": 4844, "event": "User jsmith ran: sudo cat /etc/shadow",      "user": "jsmith",      "severity": "critical", "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T02:22:48Z", "host": "srv-prod-01", "process": "bash",          "pid": 4857, "event": "Command: echo cHl0aG9uMyAtYyAnaW1wb3J0...',","user": "jsmith",      "severity": "critical", "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T02:24:17Z", "host": "srv-prod-01", "process": "python3",       "pid": 4871, "event": "Process started by jsmith",                  "user": "jsmith",      "severity": "high",     "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T02:25:00Z", "host": "srv-prod-01", "process": "rsync",         "pid": 4885, "event": "File transfer to 198.51.100.77:/data/out",   "user": "jsmith",      "severity": "critical", "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T03:00:12Z", "host": "srv-db-01",   "process": "mysqld",        "pid": 2211, "event": "Query: SELECT * FROM customers LIMIT 50000", "user": "app_svc",     "severity": "high",     "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T03:02:45Z", "host": "srv-db-01",   "process": "mysqld",        "pid": 2219, "event": "Export to /tmp/customers_export.csv",        "user": "app_svc",     "severity": "critical", "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T08:30:00Z", "host": "srv-prod-01", "process": "systemd",       "pid": 1,    "event": "Service nginx started",                      "user": "root",        "severity": "info",     "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T09:00:00Z", "host": "srv-prod-02", "process": "cron",          "pid": 1234, "event": "Backup job started",                         "user": "backup_svc",  "severity": "info",     "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T10:15:33Z", "host": "srv-hr-01",   "process": "sshd",          "pid": 5100, "event": "Login from 10.0.0.5 as jsmith",              "user": "jsmith",      "severity": "info",     "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T10:18:22Z", "host": "srv-hr-01",   "process": "sshd",          "pid": 5111, "event": "Login from 10.0.0.5 as jsmith (second host)","user": "jsmith",      "severity": "medium",   "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T10:21:05Z", "host": "srv-fin-01",  "process": "sshd",          "pid": 6700, "event": "Login from 10.0.0.5 as jsmith (third host)", "user": "jsmith",      "severity": "high",     "data_classification": "SIMULATED"},
            {"timestamp": f"{day_str}T12:00:00Z", "host": "srv-prod-01", "process": "logrotate",     "pid": 7001, "event": "Log rotation completed",                     "user": "root",        "severity": "info",     "data_classification": "SIMULATED"},
        ]
        json.dump(events, f, indent=2)

    # --- Sample Network Logs TXT ---
    txt_path = 'sample_data/sample_network_logs.txt'
    with open(txt_path, 'w') as f:
        lines = [
            '# SIMULATED NETWORK LOGS - Demonstration data only',
            f'{mon_day} 02:10:01 firewall kernel: [UFW BLOCK] IN=eth0 SRC={SUSPICIOUS_IP_1} DST=10.0.0.5 PROTO=TCP DPT=22',
            f'{mon_day} 02:10:03 firewall kernel: [UFW BLOCK] IN=eth0 SRC={SUSPICIOUS_IP_1} DST=10.0.0.5 PROTO=TCP DPT=22',
            f'{mon_day} 02:10:07 firewall kernel: [UFW BLOCK] IN=eth0 SRC={SUSPICIOUS_IP_1} DST=10.0.0.5 PROTO=TCP DPT=23',
            f'{mon_day} 02:10:11 firewall kernel: [UFW BLOCK] IN=eth0 SRC={SUSPICIOUS_IP_1} DST=10.0.0.5 PROTO=TCP DPT=3389',
            f'{mon_day} 02:11:04 firewall kernel: [UFW ALLOW] IN=eth0 SRC={SUSPICIOUS_IP_1} DST=10.0.0.5 PROTO=TCP DPT=22',
            f'{mon_day} 02:11:04 dns srv-ns-01: query[A] malware-c2-domain.xyz from {SUSPICIOUS_IP_1}',
            f'{mon_day} 02:12:19 dns srv-ns-01: query[A] data-exfil-endpoint.net from 10.0.0.5',
            f'{mon_day} 02:14:55 firewall kernel: [UFW BLOCK] IN=eth0 SRC={SUSPICIOUS_IP_1} DST=10.0.0.5 PROTO=TCP DPT=445',
            f'{mon_day} 02:17:00 firewall kernel: [UFW ALLOW] IN=eth0 SRC={SUSPICIOUS_IP_2} DST=10.0.0.5 PROTO=TCP DPT=22',
            f'{mon_day} 02:25:03 fw01 pf: pass out on eth0 inet proto tcp 10.0.0.5:{SUSPICIOUS_IP_2} flags S/SA',
            f'{mon_day} 02:25:03 fw01 pf: OUTBOUND DATA 1.4GB to {SUSPICIOUS_IP_2}',
            f'{mon_day} 08:00:00 fw01 pf: pass in on eth0 inet proto tcp 10.0.0.5:10.0.1.100',
            f'{mon_day} 08:30:00 fw01 pf: pass in on eth0 inet proto tcp 192.168.1.15:10.0.0.5',
            f'{mon_day} 09:00:00 dns srv-ns-01: query[A] internal-app.company.local from 10.0.0.5',
            f'{mon_day} 03:00:00 dns srv-ns-01: query[TXT] _dmarc.malware-c2-domain.xyz from {SUSPICIOUS_IP_1}',
            f'{mon_day} 09:12:00 fw01 pf: pass in on eth0 inet proto tcp 10.0.0.23:10.0.1.100',
            f'{mon_day} 10:00:00 fw01 bandwidth: summary: 1.4GB outbound anomaly detected',
        ]
        f.write('\n'.join(lines))

    return csv_path, json_path, txt_path


def seed_database(csv_path, json_path, txt_path):
    """Populate the database with realistic fictional sample data."""
    with app.app_context():
        db.drop_all()
        db.create_all()
        print('✓ Database tables created')

        # ── USERS ────────────────────────────────────────────────────────────
        admin = User(
            username='admin',
            email='admin@cybertrace.ai',
            password_hash=hash_password('CyberTrace2024!'),
            role='admin',
            is_active=True
        )
        investigator = User(
            username='investigator',
            email='investigator@cybertrace.ai',
            password_hash=hash_password('Invest2024!'),
            role='investigator',
            is_active=True
        )
        viewer = User(
            username='analyst',
            email='analyst@cybertrace.ai',
            password_hash=hash_password('Analyst2024!'),
            role='viewer',
            is_active=True
        )
        db.session.add_all([admin, investigator, viewer])
        db.session.flush()
        print('✓ Users created')

        # ── CASES ─────────────────────────────────────────────────────────────
        case1 = Case(
            case_id='CT-2024-001',
            title='Operation NightHawk — Unauthorized Server Access',
            description=(
                'Unauthorized access to production server srv-prod-01 detected on 2024-11-15. '
                'Threat actor gained entry via brute force SSH from IP 203.0.113.42, performed '
                'privilege escalation and accessed sensitive credential files. Data exfiltration suspected.'
            ),
            status='active',
            priority='critical',
            investigator_id=investigator.id
        )
        case2 = Case(
            case_id='CT-2024-002',
            title='DataBreach Investigation — Customer Records Exfiltration',
            description=(
                'Suspected exfiltration of customer PII database (approx. 50,000 records). '
                'Large outbound transfer of 1.4GB detected to external IP 198.51.100.77. '
                'Origin account jsmith; investigation ongoing.'
            ),
            status='active',
            priority='high',
            investigator_id=investigator.id
        )
        case3 = Case(
            case_id='CT-2024-003',
            title='Insider Threat — Finance Department Anomaly',
            description=(
                'Anomalous access patterns detected from Finance department employee account. '
                'User jsmith accessed HR, Finance, and Production systems within 11 minutes '
                'indicating potential lateral movement or compromised credentials.'
            ),
            status='open',
            priority='medium',
            investigator_id=investigator.id
        )
        db.session.add_all([case1, case2, case3])
        db.session.flush()
        print('✓ Cases created')

        # ── EVIDENCE ─────────────────────────────────────────────────────────
        from app.utils.hashing import compute_sha256
        def make_evidence(ev_id, case_id, fp, ftype, desc, uploader_id):
            size = os.path.getsize(fp) if os.path.exists(fp) else 0
            sha = compute_sha256(fp) if os.path.exists(fp) else 'simulated-sha256-hash'
            return Evidence(
                evidence_id=ev_id,
                case_id=case_id,
                filename=os.path.basename(fp),
                original_filename=os.path.basename(fp),
                file_path=fp,
                file_size=size,
                file_type=ftype,
                sha256_hash=sha,
                uploaded_by=uploader_id,
                description=desc,
                status='analyzed',
                integrity_verified=True,
                integrity_check_at=datetime.utcnow()
            )

        ev1 = make_evidence('EV-0001', case1.id, csv_path, 'csv', 'SSH authentication log — Nov 15 2024', investigator.id)
        ev2 = make_evidence('EV-0002', case1.id, json_path, 'json', 'System event log — Nov 15 2024', investigator.id)
        ev3 = make_evidence('EV-0003', case2.id, txt_path, 'txt', 'Firewall/network logs — Nov 15 2024', investigator.id)
        db.session.add_all([ev1, ev2, ev3])
        db.session.flush()
        print('✓ Evidence records created')

        # ── LOG RECORDS ───────────────────────────────────────────────────────
        base = datetime.utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(days=1)

        log_entries = []

        # Normal logins
        for i, (hr, usr, ip) in enumerate([
            (8, 'jsmith', '10.0.0.5'), (8, 'mdavis', '10.0.0.12'),
            (8, 'admin_user', '192.168.1.15'), (9, 'rjohnson', '10.0.0.23'),
            (9, 'lstewart', '172.16.0.8'), (10, 'bwilson', '10.0.1.100'),
            (13, 'jsmith', '10.0.0.5'), (14, 'mdavis', '10.0.0.12'),
            (15, 'admin_user', '192.168.1.15'), (16, 'rjohnson', '10.0.0.23'),
        ]):
            log_entries.append(LogRecord(
                evidence_id=ev1.id, case_id=case1.id,
                timestamp=base.replace(hour=hr, minute=random.randint(0, 59)),
                source_ip=ip, username=usr,
                event_type='login_success',
                event_description=f'Successful SSH login for user {usr} from {ip}',
                severity='info', raw_log=f'Nov 15 {hr:02d}:{random.randint(0,59):02d}:00 sshd: Accepted password for {usr} from {ip} port 54{i:03d} ssh2',
                is_suspicious=False
            ))

        # Brute force failed logins from suspicious IP
        for i in range(12):
            ts = base.replace(hour=2, minute=15) + timedelta(seconds=i * 4)
            usernames = ['admin', 'root', 'jsmith', 'mdavis', 'lstewart', 'admin_user', 'sysadmin', 'operator', 'sa', 'guest', 'test', 'backup']
            log_entries.append(LogRecord(
                evidence_id=ev1.id, case_id=case1.id,
                timestamp=ts,
                source_ip=SUSPICIOUS_IP_1,
                username=usernames[i % len(usernames)],
                event_type='login_failure',
                event_description=f'Failed SSH login attempt for user {usernames[i%len(usernames)]} from {SUSPICIOUS_IP_1}',
                severity='high' if i < 3 else 'critical',
                raw_log=f'Nov 15 02:15:{i*7:02d} sshd: Failed password for {usernames[i%len(usernames)]} from {SUSPICIOUS_IP_1} port 4{i:04d} ssh2',
                is_suspicious=True,
                threat_category='brute_force'
            ))

        # Successful off-hours login (suspicious)
        log_entries.append(LogRecord(
            evidence_id=ev1.id, case_id=case1.id,
            timestamp=base.replace(hour=3, minute=22),
            source_ip=SUSPICIOUS_IP_2,
            username='jsmith',
            event_type='login_success',
            event_description=f'Successful SSH login for jsmith from unusual IP {SUSPICIOUS_IP_2} at 03:22 AM',
            severity='critical',
            raw_log=f'Nov 15 03:22:19 sshd: Accepted password for jsmith from {SUSPICIOUS_IP_2} port 50001 ssh2',
            is_suspicious=True,
            threat_category='off_hours_access'
        ))

        # Privilege escalation
        log_entries.append(LogRecord(
            evidence_id=ev2.id, case_id=case1.id,
            timestamp=base.replace(hour=2, minute=21),
            source_ip=SUSPICIOUS_IP_2,
            username='jsmith',
            event_type='privilege_escalation',
            event_description='User jsmith escalated privileges using sudo to access /etc/shadow',
            severity='critical',
            raw_log='Nov 15 02:21:14 sudo: jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/cat /etc/shadow',
            is_suspicious=True,
            threat_category='privilege_escalation'
        ))

        # Suspicious process (base64 encoded command)
        log_entries.append(LogRecord(
            evidence_id=ev2.id, case_id=case1.id,
            timestamp=base.replace(hour=2, minute=22),
            source_ip=SUSPICIOUS_IP_2,
            username='jsmith',
            event_type='process_exec',
            event_description='Suspicious base64-encoded command executed via bash shell',
            severity='critical',
            raw_log='Nov 15 02:22:48 bash: echo cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldC4...',
            is_suspicious=True,
            threat_category='suspicious_process'
        ))

        # Data exfiltration
        log_entries.append(LogRecord(
            evidence_id=ev2.id, case_id=case2.id,
            timestamp=base.replace(hour=2, minute=25),
            source_ip='10.0.0.5',
            destination_ip=SUSPICIOUS_IP_2,
            username='jsmith',
            event_type='data_transfer',
            event_description=f'Large file transfer (1.4 GB) from srv-prod-01 to external IP {SUSPICIOUS_IP_2}',
            severity='critical',
            raw_log=f'Nov 15 02:25:03 rsync: sent 1,459,814,400 bytes received 182 bytes 97,320,948.13 bytes/sec total size is 1,459,682,304 speedup is 1.00 to {SUSPICIOUS_IP_2}:/data/exfil/',
            is_suspicious=True,
            threat_category='data_exfiltration'
        ))

        # Lateral movement — same user, 3 hosts
        for i, (host, hr, mn) in enumerate([
            ('srv-hr-01', 10, 15), ('srv-hr-01', 10, 18), ('srv-fin-01', 10, 21)
        ]):
            log_entries.append(LogRecord(
                evidence_id=ev3.id, case_id=case3.id,
                timestamp=base.replace(hour=hr, minute=mn),
                source_ip='10.0.0.5',
                destination_ip=f'10.0.{i+2}.1',
                username='jsmith',
                event_type='network_conn',
                event_description=f'Lateral movement: jsmith accessed {host} via SSH within 11-minute window',
                severity='high',
                raw_log=f'Nov 15 {hr}:{mn}:00 sshd[5{i}00]: Accepted publickey for jsmith from 10.0.0.5 port 44{i*100} ssh2: RSA',
                is_suspicious=True,
                threat_category='lateral_movement'
            ))

        # File access sensitive paths
        for path in ['/etc/shadow', '/etc/passwd', '/home/mdavis/.ssh/id_rsa', '/var/log/auth.log']:
            log_entries.append(LogRecord(
                evidence_id=ev2.id, case_id=case1.id,
                timestamp=base.replace(hour=2, minute=23, second=random.randint(0, 59)),
                source_ip=SUSPICIOUS_IP_2,
                username='jsmith',
                event_type='file_access',
                event_description=f'Sensitive file accessed: {path}',
                severity='high',
                raw_log=f'Nov 15 02:23:{random.randint(0,59):02d} cat: open({path}, O_RDONLY)',
                is_suspicious=True
            ))

        # Normal daytime events (Day 2)
        for hr in range(8, 18):
            ip = random.choice(SAMPLE_IPS_NORMAL)
            usr = random.choice(SAMPLE_USERS_LOGS)
            log_entries.append(LogRecord(
                evidence_id=ev3.id, case_id=case3.id,
                timestamp=base.replace(hour=hr, minute=random.randint(0, 59)) + timedelta(days=1),
                source_ip=ip, username=usr,
                event_type=random.choice(['login_success', 'file_access', 'network_conn']),
                event_description=f'Normal activity: {usr} from {ip}',
                severity='info',
                raw_log=f'Nov 16 {hr}:{random.randint(0,59):02d}:00 audit: event for {usr}',
                is_suspicious=False
            ))

        db.session.add_all(log_entries)
        db.session.flush()
        print(f'✓ {len(log_entries)} log records created')

        # ── THREAT ALERTS ─────────────────────────────────────────────────────
        alerts = [
            ThreatAlert(
                alert_id='ALERT-20241115-001',
                case_id=case1.id,
                evidence_id=ev1.id,
                alert_type='brute_force',
                severity='critical',
                description=f'Brute force SSH attack detected: 12 failed login attempts within 90 seconds from {SUSPICIOUS_IP_1}',
                source_ip=SUSPICIOUS_IP_1,
                username='multiple',
                timestamp=base.replace(hour=2, minute=15),
                status='investigating'
            ),
            ThreatAlert(
                alert_id='ALERT-20241115-002',
                case_id=case1.id,
                evidence_id=ev1.id,
                alert_type='off_hours_access',
                severity='high',
                description=f'Successful login for user jsmith from unusual IP {SUSPICIOUS_IP_2} at 03:22 AM',
                source_ip=SUSPICIOUS_IP_2,
                username='jsmith',
                timestamp=base.replace(hour=3, minute=22),
                status='investigating'
            ),
            ThreatAlert(
                alert_id='ALERT-20241115-003',
                case_id=case1.id,
                evidence_id=ev2.id,
                alert_type='privilege_escalation',
                severity='critical',
                description='User jsmith accessed /etc/shadow using sudo — credential harvesting suspected',
                source_ip=SUSPICIOUS_IP_2,
                username='jsmith',
                timestamp=base.replace(hour=2, minute=21),
                status='new'
            ),
            ThreatAlert(
                alert_id='ALERT-20241115-004',
                case_id=case2.id,
                evidence_id=ev2.id,
                alert_type='data_exfiltration',
                severity='critical',
                description=f'1.4 GB outbound data transfer to external IP {SUSPICIOUS_IP_2} — customer PII exfiltration suspected',
                source_ip='10.0.0.5',
                username='jsmith',
                timestamp=base.replace(hour=2, minute=25),
                status='investigating'
            ),
            ThreatAlert(
                alert_id='ALERT-20241115-005',
                case_id=case3.id,
                evidence_id=ev3.id,
                alert_type='lateral_movement',
                severity='high',
                description='User jsmith accessed srv-hr-01, srv-hr-01, and srv-fin-01 within 11 minutes — lateral movement pattern',
                source_ip='10.0.0.5',
                username='jsmith',
                timestamp=base.replace(hour=10, minute=15),
                status='new'
            ),
            ThreatAlert(
                alert_id='ALERT-20241115-006',
                case_id=case1.id,
                evidence_id=ev2.id,
                alert_type='suspicious_process',
                severity='critical',
                description='Base64-encoded command executed via bash shell — potential malware execution or obfuscation',
                source_ip=SUSPICIOUS_IP_2,
                username='jsmith',
                timestamp=base.replace(hour=2, minute=22),
                status='investigating'
            ),
        ]
        db.session.add_all(alerts)
        db.session.flush()
        print(f'✓ {len(alerts)} threat alerts created')

        # ── AUDIT LOG ─────────────────────────────────────────────────────────
        audit_entries = [
            AuditLog(user_id=admin.id,       action='LOGIN_SUCCESS',      resource_type='auth', ip_address='10.0.0.1', details='Admin logged in'),
            AuditLog(user_id=investigator.id, action='LOGIN_SUCCESS',      resource_type='auth', ip_address='10.0.0.5', details='Investigator logged in'),
            AuditLog(user_id=investigator.id, action='CASE_CREATED',       resource_type='case', resource_id='CT-2024-001', ip_address='10.0.0.5', details='Created Operation NightHawk case'),
            AuditLog(user_id=investigator.id, action='EVIDENCE_UPLOADED',  resource_type='evidence', resource_id='EV-0001', ip_address='10.0.0.5', details='Uploaded auth log CSV'),
            AuditLog(user_id=investigator.id, action='EVIDENCE_ANALYZED',  resource_type='evidence', resource_id='EV-0001', ip_address='10.0.0.5', details='Parsed 50 log records'),
            AuditLog(user_id=investigator.id, action='THREAT_SCAN',        resource_type='case', resource_id='CT-2024-001', ip_address='10.0.0.5', details='6 threat alerts detected'),
            AuditLog(user_id=investigator.id, action='INTEGRITY_CHECK',    resource_type='evidence', resource_id='EV-0001', ip_address='10.0.0.5', details='Hash verified OK'),
            AuditLog(user_id=admin.id,        action='CASE_CREATED',       resource_type='case', resource_id='CT-2024-002', ip_address='10.0.0.1', details='Created DataBreach case'),
            AuditLog(user_id=investigator.id, action='REPORT_GENERATED',   resource_type='case', resource_id='CT-2024-001', ip_address='10.0.0.5', details='Generated investigation report'),
        ]
        db.session.add_all(audit_entries)

        # ── CASE NOTES ────────────────────────────────────────────────────────
        notes = [
            CaseNote(case_id=case1.id, author_id=investigator.id, content='Initial analysis confirms brute force attack from 203.0.113.42. 12 failed login attempts in 90 seconds. Recommend immediate IP block and password reset for affected accounts.', note_type='finding'),
            CaseNote(case_id=case1.id, author_id=investigator.id, content='Successful login from 198.51.100.77 at 03:22 AM for user jsmith. This IP is not in our approved VPN/office IP list. Likely stolen credentials used by threat actor.', note_type='finding'),
            CaseNote(case_id=case1.id, author_id=admin.id, content='PRIORITY ACTION: Reset jsmith password, revoke active sessions, enforce MFA. Coordinate with HR for insider threat assessment.', note_type='action_item'),
            CaseNote(case_id=case2.id, author_id=investigator.id, content='1.4GB outbound transfer to 198.51.100.77 at 02:25 AM. Query logs confirm SELECT * FROM customers run against production DB at 03:00 AM. 50,000+ records likely exfiltrated.', note_type='finding'),
            CaseNote(case_id=case3.id, author_id=investigator.id, content='jsmith accessed 3 different internal hosts within 11 minutes. Pattern is consistent with lateral movement. Need to determine if credential compromise or intentional insider activity.', note_type='finding'),
        ]
        db.session.add_all(notes)

        db.session.commit()
        print('✓ Case notes and audit log created')
        print('\n' + '='*55)
        print('  CYBERTRACE AI — Database Initialized Successfully!')
        print('='*55)
        print('\n  LOGIN CREDENTIALS:')
        print('  ─────────────────────────────────────────────')
        print('  Admin:       admin@cybertrace.ai / CyberTrace2024!')
        print('  Investigator: investigator@cybertrace.ai / Invest2024!')
        print('  Analyst:     analyst@cybertrace.ai / Analyst2024!')
        print('\n  NOTE: All sample data is SIMULATED for demonstration.')
        print('='*55 + '\n')


if __name__ == '__main__':
    csv_path, json_path, txt_path = create_sample_files()
    print('✓ Sample data files created')
    seed_database(csv_path, json_path, txt_path)
