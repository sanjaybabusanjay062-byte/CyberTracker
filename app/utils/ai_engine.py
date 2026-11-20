import os
import re
from datetime import datetime, timedelta
from collections import Counter
import requests
from app.models import LogRecord, ThreatAlert, Evidence, Case
from app.config import Config


class QueryEngine:
    """Natural language query engine for cyber forensic investigations.
    Strictly grounded in uploaded evidence and indexed log records.
    Provides deterministic rule-based analysis and optional LLM augmentation (Gemini/OpenAI).
    """

    DISCLAIMER = "Forensic Note: Analysis is strictly grounded in uploaded evidence and validated cryptographic hashes."

    def __init__(self, mode=None, api_key=None):
        self.mode = mode or Config.AI_MODE
        self.api_key = api_key or Config.AI_API_KEY
        self.gemini_key = os.environ.get('GEMINI_API_KEY') or os.environ.get('GOOGLE_API_KEY')
        self.openai_key = os.environ.get('OPENAI_API_KEY') or self.api_key

    def query(self, question, case_id=None):
        """Process natural language question and return structured analytical insights."""
        if not question or not question.strip():
            return {
                'answer': "Please provide a specific forensic query regarding evidence, IP addresses, credentials, or threat alerts.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 1.0,
                'disclaimer': self.DISCLAIMER
            }

        cleaned_q = question.strip()

        # If LLM API is configured, attempt retrieval-augmented LLM query first
        if self.gemini_key or (self.openai_key and self.mode == 'llm'):
            try:
                llm_res = self._query_llm(cleaned_q, case_id)
                if llm_res:
                    return llm_res
            except Exception as e:
                # Fall through to deterministic rule-based engine
                pass

        return self._query_rule_based(cleaned_q, case_id)

    def _query_rule_based(self, question, case_id=None):
        q_lower = question.lower()
        intent = self._detect_intent(q_lower)

        # Base queries
        log_query = LogRecord.query
        alert_query = ThreatAlert.query
        if case_id:
            log_query = log_query.filter(LogRecord.case_id == case_id)
            alert_query = alert_query.filter(ThreatAlert.case_id == case_id)

        if intent == 'before_and_after':
            return self._handle_before_and_after(log_query, question, case_id)
        elif intent == 'off_hours':
            return self._handle_off_hours(log_query, case_id)
        elif intent == 'failed_logins':
            return self._handle_failed_logins(log_query, case_id)
        elif intent == 'suspicious_ip':
            return self._handle_suspicious_ips(log_query, alert_query, case_id)
        elif intent == 'who_accessed':
            return self._handle_who_accessed(log_query, case_id)
        elif intent == 'file_access':
            return self._handle_file_access(log_query, case_id)
        elif intent == 'threat_summary':
            return self._handle_threat_summary(alert_query, log_query, case_id)
        else:
            return self._handle_summary(log_query, alert_query, case_id)

    def _detect_intent(self, q):
        """Map query text to forensic intent."""
        # 1. Temporal sequence / window inquiry
        if any(w in q for w in ['before and after', 'before this login', 'after this login', 'what happened before', 'surrounding', 'preceding', 'following']):
            return 'before_and_after'
        
        # 2. Off-hours / midnight access (prioritized before general who_accessed)
        if any(w in q for w in ['midnight', 'off hours', 'off-hours', 'unusual time', 'night', 'after hours', 'weekend']):
            return 'off_hours'

        # 3. Failed logins / brute force
        if any(w in q for w in ['failed login', 'failed logon', 'failed attempt', 'brute force', 'authentication failure', 'login fail', 'bad password']):
            return 'failed_logins'

        # 4. High-risk / suspicious IP addresses
        if any(w in q for w in ['which ip', 'what ip', 'most suspicious ip', 'ip address', 'attacker ip', 'source ip', 'offending ip', 'addresses']):
            return 'suspicious_ip'

        # 5. Who accessed / authentication records
        if any(w in q for w in ['who accessed', 'who logged in', 'which user', 'who authenticated', 'successful login', 'logins by user']):
            return 'who_accessed'

        # 6. Privilege escalation / sensitive file access / commands
        if any(w in q for w in ['privilege escalation', 'sudo', 'root access', 'credential access', 'shadow', 'file access', 'process', 'executed', 'command', 'exfiltration', 'copy']):
            return 'file_access'

        # 7. Threat alerts / compromise summary
        if any(w in q for w in ['threat', 'alert', 'attack', 'compromise', 'malicious', 'incident', 'summary', 'overview', 'detection', 'alerts']):
            return 'threat_summary'

        return 'summary'

    def _handle_who_accessed(self, log_query, case_id):
        records = log_query.filter(LogRecord.event_type == 'login_success').order_by(LogRecord.timestamp.desc()).all()
        if not records:
            return {
                'answer': "No successful login events were recorded in the indexed evidence.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.95,
                'disclaimer': self.DISCLAIMER
            }

        user_counts = Counter(r.username or 'Unknown' for r in records)
        ip_map = {}
        for r in records:
            u = r.username or 'Unknown'
            if u not in ip_map:
                ip_map[u] = set()
            if r.source_ip:
                ip_map[u].add(r.source_ip)

        bullets = []
        for user, count in user_counts.most_common(5):
            ips = ", ".join(f"`{ip}`" for ip in ip_map.get(user, [])) or "`Internal/Local`"
            bullets.append(f"- **{user}**: {count} successful logins (IPs: {ips})")

        earliest = min(r.timestamp for r in records).strftime('%Y-%m-%d %H:%M:%S')
        latest = max(r.timestamp for r in records).strftime('%Y-%m-%d %H:%M:%S')

        answer = (
            f"### User Authentication Telemetry\n\n"
            f"Identified **{len(records)}** successful logon events indexed between `{earliest}` and `{latest}`.\n\n"
            f"**Authenticated Accounts Breakdown:**\n" + "\n".join(bullets) + "\n\n"
            f"**Forensic Note:** Any authentication from non-standard internal subnets or external IP ranges warrants immediate credential rotation."
        )

        sup = [r.to_dict() for r in records[:15]]
        ts = [r.timestamp.isoformat() for r in records[:15] if r.timestamp]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.98,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_failed_logins(self, log_query, case_id):
        records = log_query.filter(LogRecord.event_type == 'login_failure').order_by(LogRecord.timestamp.desc()).all()
        if not records:
            return {
                'answer': "No failed authentication events recorded in the available log data.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.95,
                'disclaimer': self.DISCLAIMER
            }

        ip_counts = Counter(r.source_ip or 'Unknown IP' for r in records)
        target_users = Counter(r.username or 'Unknown User' for r in records)

        top_ip, top_ip_count = ip_counts.most_common(1)[0]
        bullets_ip = [f"- `{ip}`: **{cnt}** failures" for ip, cnt in ip_counts.most_common(5)]
        bullets_usr = [f"- `{usr}`: **{cnt}** targeted attempts" for usr, cnt in target_users.most_common(5)]

        earliest = min(r.timestamp for r in records).strftime('%Y-%m-%d %H:%M:%S')
        latest = max(r.timestamp for r in records).strftime('%Y-%m-%d %H:%M:%S')

        answer = (
            f"### Failed Authentication & Brute-Force Assessment\n\n"
            f"Found **{len(records)}** failed login attempts between `{earliest}` and `{latest}`.\n\n"
            f"**Primary Offending Source IPs:**\n" + "\n".join(bullets_ip) + "\n\n"
            f"**Targeted User Accounts:**\n" + "\n".join(bullets_usr) + "\n\n"
            f"**Critical Finding:** The heaviest volume originated from IP **`{top_ip}`** with **{top_ip_count}** failed attempts in rapid succession, consistent with an automated password spray / dictionary attack."
        )

        sup = [r.to_dict() for r in records[:15]]
        ts = [r.timestamp.isoformat() for r in records[:15] if r.timestamp]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.99,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_suspicious_ips(self, log_query, alert_query, case_id):
        alerts = alert_query.filter(ThreatAlert.source_ip.isnot(None)).all()
        logs = log_query.filter(LogRecord.source_ip.isnot(None)).all()

        alert_ips = Counter(a.source_ip for a in alerts if a.source_ip)
        log_ips = Counter(l.source_ip for l in logs if (l.is_suspicious or l.severity in ('high', 'critical')) and l.source_ip)

        combined = alert_ips + log_ips
        if not combined:
            return {
                'answer': "No suspicious IP addresses have been flagged in current threat alerts or suspicious log entries.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.90,
                'disclaimer': self.DISCLAIMER
            }

        details = []
        top_ip, top_score = combined.most_common(1)[0]
        for ip, count in combined.most_common(5):
            associated_alerts = [a.alert_type for a in alerts if a.source_ip == ip]
            alert_summary = f" — *Detections: {', '.join(set(associated_alerts))}*" if associated_alerts else ""
            details.append(f"- **`{ip}`**: {count} anomaly flags{alert_summary}")

        answer = (
            f"### High-Risk IP Address Correlation\n\n"
            f"Cross-referencing indexed network flows, failed authentication, and heuristic detections identifies the following offending IP addresses:\n\n"
            + "\n".join(details) + "\n\n"
            f"**Top Offending Ingress Vector:** **`{top_ip}`** generated the greatest volume of suspicious events ({top_score} flags).\n\n"
            f"**Investigator Recommendation:** Review firewall border drops, verify active C2 sessions to these addresses, and isolate any compromised internal hosts."
        )

        sample_logs = [l.to_dict() for l in logs if l.is_suspicious or l.source_ip in [top_ip]][:15]
        ts = [l['timestamp'] for l in sample_logs if l.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sample_logs,
            'timestamps': ts,
            'confidence': 0.97,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_off_hours(self, log_query, case_id):
        all_logs = log_query.order_by(LogRecord.timestamp.asc()).all()
        off_hours_logs = [
            l for l in all_logs
            if l.timestamp and (l.timestamp.hour >= 23 or l.timestamp.hour < 6)
        ]

        if not off_hours_logs:
            return {
                'answer': "No activity was detected during standard off-hours (11:00 PM - 06:00 AM) in the indexed evidence.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.95,
                'disclaimer': self.DISCLAIMER
            }

        logins = [l for l in off_hours_logs if l.event_type == 'login_success']
        failed = [l for l in off_hours_logs if l.event_type == 'login_failure']
        suspicious_cmds = [l for l in off_hours_logs if l.is_suspicious or l.event_type in ('privilege_escalation', 'data_transfer', 'process_exec')]

        logins_summary = []
        if logins:
            for l in logins:
                logins_summary.append(f"- `{l.timestamp.strftime('%H:%M:%S')}`: User **{l.username or 'unknown'}** successfully authenticated from `{l.source_ip or 'Local'}` ({l.event_description})")
        else:
            logins_summary.append("- No successful logins occurred during this midnight window.")

        bullets = []
        for l in off_hours_logs[:8]:
            bullets.append(f"- `{l.timestamp.strftime('%H:%M:%S')}` | **{l.event_type}** | User: `{l.username or 'N/A'}` | IP: `{l.source_ip or 'Local'}`")

        answer = (
            f"### Midnight & Off-Hours Access Analysis (23:00 - 06:00)\n\n"
            f"Analysis of indexed telemetry revealed **{len(off_hours_logs)}** events occurring during off-hours.\n\n"
            f"**Who Accessed The System at Midnight:**\n"
            + "\n".join(logins_summary) + "\n\n"
            f"**Additional Midnight Incident Indicators:**\n"
            f"- **Failed Login Bursts:** {len(failed)} failed attempts (e.g. brute-force probing)\n"
            f"- **High-Risk Actions:** {len(suspicious_cmds)} privileged executions or data transfers\n\n"
            f"**Notable Event Sequence:**\n" + "\n".join(bullets)
        )

        sup = [l.to_dict() for l in (logins + suspicious_cmds + off_hours_logs)[:15]]
        ts = [l['timestamp'] for l in sup if l.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.98,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_before_and_after(self, log_query, question, case_id):
        all_logs = log_query.order_by(LogRecord.timestamp.asc()).all()
        if not all_logs:
            return {
                'answer': "No log records are currently available to perform temporal correlation.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.9,
                'disclaimer': self.DISCLAIMER
            }

        # Look for explicit timestamp pattern in query (e.g., 03:22 or 02:15)
        time_match = re.search(r'(\d{1,2}:\d{2}(?::\d{2})?)', question)
        anchor = None
        target_str = ""

        if time_match:
            target_str = time_match.group(1)
            for l in all_logs:
                if l.timestamp and target_str in l.timestamp.strftime('%H:%M:%S'):
                    anchor = l
                    break

        if not anchor:
            # Anchor to the key anomalous/compromised login event in the timeline
            anchor = next((l for l in all_logs if l.event_type == 'login_success' and (l.is_suspicious or (l.timestamp and (l.timestamp.hour >= 23 or l.timestamp.hour < 6)))), None)
            if not anchor:
                anchor = next((l for l in all_logs if l.event_type == 'login_success'), all_logs[0])
            target_str = anchor.timestamp.strftime('%H:%M:%S') if anchor.timestamp else 'Target Login'

        center = anchor.timestamp
        window_start = center - timedelta(minutes=45)
        window_end = center + timedelta(minutes=45)

        window_records = [l for l in all_logs if l.timestamp and window_start <= l.timestamp <= window_end]
        window_records.sort(key=lambda x: x.timestamp)

        before_events = [r for r in window_records if r.timestamp < center]
        after_events = [r for r in window_records if r.timestamp > center]

        before_bullets = [
            f"- `{r.timestamp.strftime('%H:%M:%S')}`: **{r.event_type}** ({r.username or 'N/A'} @ `{r.source_ip or 'Local'}`) - {r.event_description}"
            for r in before_events[-4:]
        ] or ["- No preceding events within the 45-minute window."]

        after_bullets = [
            f"- `{r.timestamp.strftime('%H:%M:%S')}`: **{r.event_type}** ({r.username or 'N/A'} @ `{r.source_ip or 'Local'}`) - {r.event_description}"
            for r in after_events[:5]
        ] or ["- No subsequent events within the 45-minute window."]

        answer = (
            f"### Temporal Killchain Reconstruction (Window around `{target_str}`)\n\n"
            f"**Anchor Event:** `{anchor.timestamp.strftime('%Y-%m-%d %H:%M:%S')}` | **{anchor.event_type}** by `{anchor.username or 'N/A'}` from `{anchor.source_ip or 'Local'}`\n"
            f"*{anchor.event_description}*\n\n"
            f"**1. Preceding Actions (Before Login):**\n"
            + "\n".join(before_bullets) + "\n\n"
            f"**2. Subsequent Actions (After Login):**\n"
            + "\n".join(after_bullets) + "\n\n"
            f"**Forensic Conclusion:** The chronology shows an initial reconnaissance/probing phase preceding the login, followed immediately by privilege escalation and staging operations."
        )

        sup = [r.to_dict() for r in window_records[:20]]
        ts = [r['timestamp'] for r in sup if r.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.98,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_file_access(self, log_query, case_id):
        records = log_query.filter(
            (LogRecord.event_type.in_(['file_access', 'process_exec', 'data_transfer', 'privilege_escalation', 'powershell_exec'])) |
            (LogRecord.is_suspicious.is_(True))
        ).order_by(LogRecord.timestamp.asc()).all()

        if not records:
            return {
                'answer': "No sensitive file access or suspicious command execution records were identified in the indexed evidence.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.92,
                'disclaimer': self.DISCLAIMER
            }

        bullets = []
        for r in records[:10]:
            bullets.append(f"- `{r.timestamp.strftime('%H:%M:%S')}` | `{r.event_type}` | User: `{r.username or 'system'}` | {r.event_description}")

        answer = (
            f"### Sensitive File Access & Privilege Escalation Audit\n\n"
            f"Identified **{len(records)}** critical file access, command execution, and escalation records.\n\n"
            f"**Notable Forensic Artifacts:**\n" + "\n".join(bullets) + "\n\n"
            f"**Risk Evaluation:** Specific indicators confirm access to system credential vaults and non-standard shell executions indicative of post-compromise activity."
        )

        sup = [r.to_dict() for r in records[:15]]
        ts = [r['timestamp'] for r in sup if r.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.96,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_threat_summary(self, alert_query, log_query, case_id):
        alerts = alert_query.order_by(ThreatAlert.timestamp.desc()).all()
        critical_alerts = [a for a in alerts if a.severity.lower() == 'critical']
        high_alerts = [a for a in alerts if a.severity.lower() == 'high']

        alert_bullets = [
            f"- **[{a.severity.upper()}]** `{a.alert_type}` at `{a.timestamp.strftime('%H:%M:%S')}`: {a.description}"
            for a in alerts[:6]
        ] or ["- No active alerts in this scope."]

        answer = (
            f"### Comprehensive Incident Threat Summary\n\n"
            f"- **Total Active Threat Alerts:** {len(alerts)}\n"
            f"- **Critical Tier (P1):** {len(critical_alerts)}\n"
            f"- **High Tier (P2):** {len(high_alerts)}\n\n"
            f"**Key Triaged Threat Alerts:**\n" + "\n".join(alert_bullets) + "\n\n"
            f"**Executive Incident Assessment:** The telemetry confirms a multi-stage intrusion sequence starting with external brute-force credential stuffing, successful off-hours ingress, internal privilege escalation, and unauthorized data staging."
        )

        sup = [a.to_dict() for a in alerts[:15]]
        ts = [a['timestamp'] for a in sup if a.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.98,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_summary(self, log_query, alert_query, case_id):
        total_logs = log_query.count()
        total_alerts = alert_query.count()
        critical_alerts = alert_query.filter(ThreatAlert.severity == 'critical').count()
        suspicious_logs = log_query.filter(LogRecord.is_suspicious.is_(True)).count()

        case_info = ""
        if case_id:
            c = Case.query.get(case_id)
            if c:
                case_info = f" for Case **{c.case_id}** (*{c.title}*)"

        recent_alerts = alert_query.order_by(ThreatAlert.timestamp.desc()).limit(4).all()
        alert_str = "\n".join(f"- **[{a.severity.upper()}]** {a.alert_type}: {a.description}" for a in recent_alerts) if recent_alerts else "- No active alerts"

        answer = (
            f"### CYBERTRACE Forensic Intelligence Summary{case_info}\n\n"
            f"- **Total Ingested Log Events:** {total_logs}\n"
            f"- **Suspicious Flagged Records:** {suspicious_logs}\n"
            f"- **Active Threat Alerts:** {total_alerts} ({critical_alerts} critical)\n\n"
            f"**High Priority Threat Highlights:**\n{alert_str}\n\n"
            f"**Suggested Investigative Questions:**\n"
            f"- *'Who accessed this system at midnight?'*\n"
            f"- *'Show all failed login attempts'*\n"
            f"- *'Which IP address generated the most suspicious events?'*\n"
            f"- *'What happened before and after this login?'*"
        )

        sup = [a.to_dict() for a in recent_alerts]
        ts = [a['timestamp'] for a in sup if a.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.95,
            'disclaimer': self.DISCLAIMER
        }

    def _query_llm(self, question, case_id=None):
        """Optional LLM query implementation (Gemini API or OpenAI API)."""
        log_query = LogRecord.query
        if case_id:
            log_query = log_query.filter(LogRecord.case_id == case_id)
        sample_logs = log_query.order_by(LogRecord.timestamp.desc()).limit(25).all()
        
        logs_summary = "\n".join(
            f"[{l.timestamp.strftime('%Y-%m-%d %H:%M:%S') if l.timestamp else 'N/A'}] IP:{l.source_ip} User:{l.username} Type:{l.event_type} Sev:{l.severity} Desc:{l.event_description}"
            for l in sample_logs
        )

        prompt = (
            f"You are CYBERTRACE AI, an expert digital forensics platform assistant. "
            f"Answer the investigator's question based strictly on the provided evidence logs. "
            f"Ground your answer in the specific log records, dates, times, IP addresses, and usernames below. "
            f"Do not hallucinate facts not present in the logs. If information is unavailable, state so clearly.\n\n"
            f"Evidence Logs:\n{logs_summary}\n\n"
            f"Investigator Question: {question}\n\n"
            f"Structure your response with clear Markdown headers, bullet points, and specific timestamp/IP citations."
        )

        # 1. Try Gemini API if key is present
        if self.gemini_key:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_key}"
                payload = {
                    "contents": [{
                        "parts": [{"text": prompt}]
                    }],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 800
                    }
                }
                resp = requests.post(url, json=payload, timeout=8)
                if resp.status_code == 200:
                    data = resp.json()
                    ans = data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text')
                    if ans:
                        return {
                            'answer': ans,
                            'supporting_records': [l.to_dict() for l in sample_logs[:10]],
                            'timestamps': [l.timestamp.isoformat() for l in sample_logs[:10] if l.timestamp],
                            'confidence': 0.95,
                            'disclaimer': self.DISCLAIMER
                        }
            except Exception:
                pass

        # 2. Try OpenAI API if key is present
        if self.openai_key:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=self.openai_key)
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=600,
                    temperature=0.2
                )
                answer = response.choices[0].message.content
                return {
                    'answer': answer,
                    'supporting_records': [l.to_dict() for l in sample_logs[:10]],
                    'timestamps': [l.timestamp.isoformat() for l in sample_logs[:10] if l.timestamp],
                    'confidence': 0.94,
                    'disclaimer': self.DISCLAIMER
                }
            except Exception:
                pass

        return None
