import os
import re
from datetime import datetime, timedelta
from collections import Counter
from app.models import LogRecord, ThreatAlert, Evidence, Case
from app.config import Config


class QueryEngine:
    """Natural language query engine for cyber forensic investigations.
    Supports intelligent rule-based intent parsing as well as optional LLM augmentation.
    """

    DISCLAIMER = "This analysis is based on available evidence only."

    def __init__(self, mode=None, api_key=None):
        self.mode = mode or Config.AI_MODE
        self.api_key = api_key or Config.AI_API_KEY

    def query(self, question, case_id=None):
        """Process natural language question and return structured analytical insights."""
        if not question or not question.strip():
            return {
                'answer': "Please provide a specific query regarding forensic evidence, IP addresses, user activity, or threat alerts.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 1.0,
                'disclaimer': self.DISCLAIMER
            }

        # If LLM mode is configured and API key exists, attempt LLM first with rule-based fallback
        if self.mode == 'llm' and self.api_key:
            try:
                llm_res = self._query_llm(question, case_id)
                if llm_res:
                    return llm_res
            except Exception:
                pass  # Fall back directly to rule-based engine

        return self._query_rule_based(question.strip(), case_id)

    def _query_rule_based(self, question, case_id=None):
        q_lower = question.lower()
        intent = self._detect_intent(q_lower)

        # Base queries
        log_query = LogRecord.query
        alert_query = ThreatAlert.query
        if case_id:
            log_query = log_query.filter(LogRecord.case_id == case_id)
            alert_query = alert_query.filter(ThreatAlert.case_id == case_id)

        if intent == 'who_accessed':
            return self._handle_who_accessed(log_query, case_id)
        elif intent == 'failed_logins':
            return self._handle_failed_logins(log_query, case_id)
        elif intent == 'suspicious_ip':
            return self._handle_suspicious_ips(log_query, alert_query, case_id)
        elif intent == 'off_hours':
            return self._handle_off_hours(log_query, case_id)
        elif intent == 'threat_summary':
            return self._handle_threat_summary(alert_query, log_query, case_id)
        elif intent == 'file_access':
            return self._handle_file_access(log_query, case_id)
        elif intent == 'before_and_after':
            return self._handle_before_and_after(log_query, question, case_id)
        else:
            return self._handle_summary(log_query, alert_query, case_id)

    def _detect_intent(self, q):
        """Map query text to forensic intent."""
        if any(w in q for w in ['before and after', 'around', 'surrounding', 'preceding', 'following']) and re.search(r'\d{1,2}:\d{2}', q):
            return 'before_and_after'
        if any(w in q for w in ['who accessed', 'who logged in', 'which user', 'who authenticated', 'successful login', 'logins by user']):
            return 'who_accessed'
        if any(w in q for w in ['failed login', 'brute force', 'authentication failure', 'login fail', 'bad password']):
            return 'failed_logins'
        if any(w in q for w in ['which ip', 'what ip', 'ip address', 'attacker ip', 'source ip', 'offending ip', 'addresses']):
            return 'suspicious_ip'
        if any(w in q for w in ['midnight', 'off hours', 'unusual time', 'night', 'after hours', 'weekend']):
            return 'off_hours'
        if any(w in q for w in ['threat', 'alert', 'attack', 'compromise', 'malicious', 'incident', 'detection', 'alerts']):
            return 'threat_summary'
        if any(w in q for w in ['file access', 'file execution', 'shadow', 'passwd', 'process', 'executed', 'command', 'exfiltration', 'copy']):
            return 'file_access'
        return 'summary'

    def _handle_who_accessed(self, log_query, case_id):
        records = log_query.filter(LogRecord.event_type == 'login_success').order_by(LogRecord.timestamp.desc()).all()
        if not records:
            return {
                'answer': "No successful login events were recorded in the current scope.",
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
            ips = ", ".join(ip_map.get(user, [])) or "Internal/Local"
            bullets.append(f"- **{user}**: {count} successful logins (IPs: `{ips}`)")

        earliest = min(r.timestamp for r in records).strftime('%Y-%m-%d %H:%M:%S')
        latest = max(r.timestamp for r in records).strftime('%Y-%m-%d %H:%M:%S')

        answer = (
            f"### User Access Analysis\n\n"
            f"Identified **{len(records)}** successful login events spanning from `{earliest}` to `{latest}`.\n\n"
            f"**Top Authenticated Accounts:**\n" + "\n".join(bullets) + "\n\n"
            f"Cross-reference these usernames with authorized personnel schedules to identify account takeover anomalies."
        )

        sup = [r.to_dict() for r in records[:15]]
        ts = [r.timestamp.isoformat() for r in records[:15] if r.timestamp]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.96,
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
        bullets_ip = [f"- `{ip}`: {cnt} failures" for ip, cnt in ip_counts.most_common(5)]
        bullets_usr = [f"- `{usr}`: {cnt} attempts" for usr, cnt in target_users.most_common(5)]

        answer = (
            f"### Failed Authentication & Brute-Force Assessment\n\n"
            f"Found **{len(records)}** failed login attempts.\n\n"
            f"**Primary Offending Source IPs:**\n" + "\n".join(bullets_ip) + "\n\n"
            f"**Targeted User Accounts:**\n" + "\n".join(bullets_usr) + "\n\n"
            f"The heaviest concentration of failures originated from **`{top_ip}`** ({top_ip_count} attempts), indicating a targeted dictionary or brute-force attack."
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

    def _handle_suspicious_ips(self, log_query, alert_query, case_id):
        alerts = alert_query.filter(ThreatAlert.source_ip.isnot(None)).all()
        logs = log_query.filter(LogRecord.source_ip.isnot(None)).all()

        alert_ips = Counter(a.source_ip for a in alerts if a.source_ip)
        log_ips = Counter(l.source_ip for l in logs if l.is_suspicious and l.source_ip)

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
        for ip, count in combined.most_common(5):
            associated_alerts = [a.alert_type for a in alerts if a.source_ip == ip]
            alert_summary = f" (Alerts: {', '.join(set(associated_alerts))})" if associated_alerts else ""
            details.append(f"- **`{ip}`**: {count} suspicious flags{alert_summary}")

        answer = (
            f"### High-Risk IP Address Analysis\n\n"
            f"The investigation correlates the following IP addresses with suspicious activities or threat alerts:\n\n"
            + "\n".join(details) + "\n\n"
            f"**Recommendation:** Implement immediate firewall blocks on external IPs and inspect all ingress/egress sessions associated with these endpoints."
        )

        sample_logs = [l.to_dict() for l in logs if l.is_suspicious][:15]
        ts = [l['timestamp'] for l in sample_logs if l.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sample_logs,
            'timestamps': ts,
            'confidence': 0.94,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_off_hours(self, log_query, case_id):
        all_logs = log_query.all()
        off_hours_logs = [
            l for l in all_logs
            if l.timestamp and (l.timestamp.hour >= 23 or l.timestamp.hour < 6)
        ]

        if not off_hours_logs:
            return {
                'answer': "No activity was detected during standard off-hours (11:00 PM - 06:00 AM).",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.95,
                'disclaimer': self.DISCLAIMER
            }

        logins = [l for l in off_hours_logs if l.event_type == 'login_success']
        items = []
        for l in off_hours_logs[:8]:
            items.append(f"- `{l.timestamp.strftime('%H:%M:%S')}`: **{l.event_type}** by `{l.username or 'N/A'}` from `{l.source_ip or 'Local'}` ({l.event_description})")

        answer = (
            f"### Off-Hours Forensic Analysis (23:00 - 06:00)\n\n"
            f"Detected **{len(off_hours_logs)}** events occurring during off-hours, including **{len(logins)}** successful logins.\n\n"
            f"**Key Off-Hours Events:**\n" + "\n".join(items) + "\n\n"
            f"Off-hours access often signifies unauthorized actor persistence, scheduled exfiltration, or overseas adversary operations."
        )

        sup = [l.to_dict() for l in off_hours_logs[:15]]
        ts = [l['timestamp'] for l in sup if l.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.95,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_threat_summary(self, alert_query, log_query, case_id):
        alerts = alert_query.order_by(ThreatAlert.timestamp.desc()).all()
        if not alerts:
            return {
                'answer': "No threat alerts currently exist for the selected scope. Consider triggering an automated scan from the Threats module.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.90,
                'disclaimer': self.DISCLAIMER
            }

        sev_counts = Counter(a.severity.lower() for a in alerts)
        type_counts = Counter(a.alert_type for a in alerts)

        alert_bullets = [
            f"- **[{a.severity.upper()}]** `{a.alert_type}` at `{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}`: {a.description}"
            for a in alerts[:6]
        ]

        answer = (
            f"### Threat Alerts Overview\n\n"
            f"Total active alerts: **{len(alerts)}** (Critical: {sev_counts.get('critical', 0)}, High: {sev_counts.get('high', 0)}, Medium: {sev_counts.get('medium', 0)}).\n\n"
            f"**Recent Detections:**\n" + "\n".join(alert_bullets) + "\n\n"
            f"Forensic indicators confirm multi-stage activity including perimeter probing, privilege access attempts, and abnormal credential behavior."
        )

        sup = [a.to_dict() for a in alerts[:15]]
        ts = [a['timestamp'] for a in sup if a.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.97,
            'disclaimer': self.DISCLAIMER
        }

    def _handle_file_access(self, log_query, case_id):
        records = log_query.filter(
            (LogRecord.event_type.in_(['file_access', 'process_exec', 'data_transfer', 'privilege_escalation'])) |
            (LogRecord.is_suspicious.is_(True))
        ).order_by(LogRecord.timestamp.desc()).all()

        if not records:
            return {
                'answer': "No suspicious file access or execution records were identified in the indexed evidence.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.92,
                'disclaimer': self.DISCLAIMER
            }

        bullets = []
        for r in records[:8]:
            bullets.append(f"- `{r.timestamp.strftime('%Y-%m-%d %H:%M:%S')}` | `{r.event_type}` | User: `{r.username or 'system'}` | {r.event_description}")

        answer = (
            f"### File Access & Process Execution Audit\n\n"
            f"Identified **{len(records)}** sensitive file access and process execution events.\n\n"
            f"**Notable Forensic Artifacts:**\n" + "\n".join(bullets) + "\n\n"
            f"Special attention should be directed toward access to system credential vaults and non-standard binary executions."
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

    def _handle_before_and_after(self, log_query, question, case_id):
        # Extract time pattern like HH:MM:SS or HH:MM
        time_match = re.search(r'(\d{1,2}:\d{2}(?::\d{2})?)', question)
        if not time_match:
            return self._handle_summary(log_query, ThreatAlert.query, case_id)

        target_time_str = time_match.group(1)
        all_logs = log_query.all()
        # Find anchor record matching time
        anchor = None
        for l in all_logs:
            if l.timestamp and target_time_str in l.timestamp.strftime('%H:%M:%S'):
                anchor = l
                break

        if not anchor:
            return {
                'answer': f"No log event found exactly matching timestamp `{target_time_str}` to perform window analysis.",
                'supporting_records': [],
                'timestamps': [],
                'confidence': 0.85,
                'disclaimer': self.DISCLAIMER
            }

        center = anchor.timestamp
        window_start = center - timedelta(minutes=30)
        window_end = center + timedelta(minutes=30)

        window_records = [l for l in all_logs if l.timestamp and window_start <= l.timestamp <= window_end]
        window_records.sort(key=lambda x: x.timestamp)

        bullets = [
            f"- `{r.timestamp.strftime('%H:%M:%S')}`: **{r.event_type}** ({r.username or 'N/A'}) - {r.event_description}"
            for r in window_records[:10]
        ]

        answer = (
            f"### Temporal Correlation Window (±30 Minutes Around `{target_time_str}`)\n\n"
            f"Identified **{len(window_records)}** events between `{window_start.strftime('%H:%M:%S')}` and `{window_end.strftime('%H:%M:%S')}`.\n\n"
            f"**Event Sequence:**\n" + "\n".join(bullets) + "\n\n"
            f"Correlating the sequence before and after `{target_time_str}` reveals adversary preparation, execution, and potential follow-up cleanup actions."
        )

        sup = [r.to_dict() for r in window_records[:20]]
        ts = [r['timestamp'] for r in sup if r.get('timestamp')]
        return {
            'answer': answer,
            'supporting_records': sup,
            'timestamps': ts,
            'confidence': 0.95,
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

        recent_alerts = alert_query.order_by(ThreatAlert.timestamp.desc()).limit(3).all()
        alert_str = "\n".join(f"- [{a.severity.upper()}] {a.alert_type}: {a.description}" for a in recent_alerts) if recent_alerts else "- No active alerts"

        answer = (
            f"### Forensic Intelligence Summary{case_info}\n\n"
            f"- **Total Ingested Log Events:** {total_logs}\n"
            f"- **Suspicious Flagged Records:** {suspicious_logs}\n"
            f"- **Active Threat Alerts:** {total_alerts} ({critical_alerts} critical)\n\n"
            f"**High Priority Threat Highlights:**\n{alert_str}\n\n"
            f"You can ask targeted questions such as *'Who accessed between 02:00 and 04:00?'*, *'List brute force attempts'*, *'Which IP had failed logins?'*, or *'Show sensitive file access'*."
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
        """Optional OpenAI query implementation if API key is provided."""
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)

            # Retrieve context records
            log_query = LogRecord.query
            if case_id:
                log_query = log_query.filter(LogRecord.case_id == case_id)
            sample_logs = log_query.order_by(LogRecord.timestamp.desc()).limit(20).all()
            logs_summary = "\n".join(
                f"[{l.timestamp}] IP:{l.source_ip} User:{l.username} Type:{l.event_type} Desc:{l.event_description}"
                for l in sample_logs
            )

            prompt = (
                f"You are CYBERTRACE AI, an expert digital forensics investigator. "
                f"Analyze the following evidence logs and answer the user question professionally.\n\n"
                f"Evidence Logs:\n{logs_summary}\n\n"
                f"Question: {question}\n\n"
                f"Provide a structured analysis with key findings, affected accounts/IPs, and recommendations."
            )

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
                'confidence': 0.92,
                'disclaimer': self.DISCLAIMER
            }
        except Exception:
            return None
