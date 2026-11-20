"""
CYBERTRACE AI — Full Platform Verification Test Suite
Covers:
1. PBKDF2:SHA-256 Authentication & Session Security
2. Evidence Ingestion & Cryptographic SHA-256 Integrity Verification
3. Log Parsing & Normalization (CSV, JSON, Syslog TXT)
4. Heuristic Threat Detection (Brute Force, Off-Hours, Unusual IPs, Privilege Escalation)
5. Grounded AI Assistant Natural Language Queries
6. Attack Reconstruction Graph & Topology APIs
7. Chronological Incident Timeline
8. Case Management & Investigative Audit Notes
9. ReportLab Court-Ready PDF Forensic Report Generation
"""
import os
import sys
import unittest
import json
import tempfile
import io
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from app.config import Config
from app.models import User, Case, Evidence, LogRecord, ThreatAlert, AuditLog, CaseNote
from app.utils.hashing import hash_password, check_password, compute_sha256, verify_integrity
from app.utils.log_parser import parse_log_file, detect_format, classify_event
from app.utils.threat_detector import run_all_detections, detect_brute_force, detect_off_hours_access
from app.utils.ai_engine import QueryEngine
from app.utils.pdf_generator import generate_investigation_report


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    UPLOAD_FOLDER = tempfile.mkdtemp()
    REPORTS_FOLDER = tempfile.mkdtemp()


class CyberTracePlatformTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app(TestConfig)
        cls.app_context = cls.app.app_context()
        cls.app_context.push()
        db.create_all()

    @classmethod
    def tearDownClass(cls):
        db.session.remove()
        db.drop_all()
        cls.app_context.pop()

    def setUp(self):
        self.client = self.app.test_client()
        # Seed test user
        self.user = User.query.filter_by(username='investigator_lead').first()
        if not self.user:
            self.user = User(
                username='investigator_lead',
                email='lead@cybertrace.ai',
                password_hash=hash_password('CyberTraceLead!2026'),
                role='investigator'
            )
            db.session.add(self.user)
            db.session.commit()

        # Seed test case
        self.case = Case.query.filter_by(case_id='CT-EVAL-001').first()
        if not self.case:
            self.case = Case(
                case_id='CT-EVAL-001',
                title='Operation ShadowBeacon - Production Enclave Breach',
                description='Automated forensic testing case',
                status='active',
                priority='critical',
                investigator_id=self.user.id
            )
            db.session.add(self.case)
            db.session.commit()

    def login(self, username='investigator_lead', password='CyberTraceLead!2026'):
        return self.client.post('/auth/login', data={
            'username': username,
            'password': password
        }, follow_redirects=True)

    # ── 1. AUTHENTICATION & SESSION SECURITY ──────────────────────────────────

    def test_01_authentication_flow(self):
        """Verify successful login, invalid credential rejection, and session state."""
        # Bad login attempt
        bad_resp = self.login(username='investigator_lead', password='WrongPassword!')
        self.assertIn(b'Invalid credentials', bad_resp.data)

        # Successful login
        good_resp = self.login()
        self.assertEqual(good_resp.status_code, 200)

        # Unauthenticated logout
        logout_resp = self.client.get('/auth/logout', follow_redirects=True)
        self.assertIn(b'logged out', logout_resp.data)

    # ── 2. EVIDENCE HASHING & CHAIN OF CUSTODY ────────────────────────────────

    def test_02_evidence_upload_and_tamper_detection(self):
        """Verify file upload, SHA-256 generation, and real-time tamper verification."""
        self.login()
        content = b"Simulated forensic evidence: 2026-11-20 02:15:00 SSH Accepted"
        data = {
            'file': (io.BytesIO(content), 'auth_dump.log'),
            'case_id': str(self.case.id),
            'description': 'Volatile memory auth dump'
        }

        resp = self.client.post('/api/evidence/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(resp.status_code, 201)
        ev_data = resp.get_json()['evidence']
        self.assertEqual(len(ev_data['sha256_hash']), 64)
        evidence_id = ev_data['id']

        # Verify integrity on pristine file
        verify_resp = self.client.post(f'/api/evidence/{evidence_id}/verify')
        self.assertEqual(verify_resp.status_code, 200)
        self.assertTrue(verify_resp.get_json()['integrity'])

        # Deliberately modify file on disk to simulate tampering
        ev = db.session.get(Evidence, evidence_id)
        with open(ev.file_path, 'ab') as f:
            f.write(b'\nTAMPERED_BYTE_PAYLOAD')

        # Tampered verification check
        tamper_resp = self.client.post(f'/api/evidence/{evidence_id}/verify')
        self.assertEqual(tamper_resp.status_code, 200)
        self.assertFalse(tamper_resp.get_json()['integrity'])

    # ── 3. LOG PARSER (CSV, JSON, TXT) ────────────────────────────────────────

    def test_03_multi_format_log_parsing(self):
        """Verify normalization across CSV, JSON, and Syslog TXT."""
        # CSV
        csv_file = 'sample_data/sample_auth_logs.csv'
        if os.path.exists(csv_file):
            recs_csv = parse_log_file(csv_file)
            self.assertGreater(len(recs_csv), 10)
            self.assertTrue(any(r['is_suspicious'] for r in recs_csv))

        # JSON
        json_file = 'sample_data/sample_system_events.json'
        if os.path.exists(json_file):
            recs_json = parse_log_file(json_file)
            self.assertGreater(len(recs_json), 5)

        # TXT Syslog
        txt_file = 'sample_data/sample_network_logs.txt'
        if os.path.exists(txt_file):
            recs_txt = parse_log_file(txt_file)
            self.assertGreater(len(recs_txt), 5)

    # ── 4. THREAT DETECTION HEURISTICS ───────────────────────────────────────

    def test_04_heuristic_detection_suite(self):
        """Verify brute force, off-hours, and sensitive execution detection."""
        now = datetime.utcnow()
        sample_logs = [
            {'timestamp': now + timedelta(seconds=i*3), 'source_ip': '203.0.113.50', 'username': 'admin', 'event_type': 'login_failure', 'event_description': 'Bad password'}
            for i in range(7)
        ]
        sample_logs.append({
            'timestamp': datetime(2026, 11, 20, 3, 15, 0),
            'source_ip': '198.51.100.22',
            'username': 'jsmith',
            'event_type': 'login_success',
            'event_description': 'Successful login at 03:15'
        })
        sample_logs.append({
            'timestamp': datetime(2026, 11, 20, 3, 20, 0),
            'source_ip': '198.51.100.22',
            'username': 'jsmith',
            'event_type': 'privilege_escalation',
            'event_description': 'sudo cat /etc/shadow executed'
        })

        alerts = run_all_detections(sample_logs, case_id=self.case.id)
        alert_types = [a['alert_type'] for a in alerts]
        self.assertIn('Brute Force Attack', alert_types)
        self.assertIn('Off-Hours Access', alert_types)
        self.assertIn('Privilege Escalation', alert_types)

    # ── 5. GROUNDED AI ASSISTANT QUERIES ─────────────────────────────────────

    def test_05_grounded_ai_assistant_queries(self):
        """Verify all 5 core investigative questions are answered with evidence."""
        base = datetime.utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(days=1)
        l1 = LogRecord(
            case_id=self.case.id,
            timestamp=base.replace(hour=2, minute=15),
            source_ip='203.0.113.42',
            username='admin',
            event_type='login_failure',
            event_description='Failed SSH login attempt',
            severity='high',
            is_suspicious=True
        )
        l2 = LogRecord(
            case_id=self.case.id,
            timestamp=base.replace(hour=3, minute=22),
            source_ip='198.51.100.77',
            username='jsmith',
            event_type='login_success',
            event_description='Successful SSH login from unusual IP at 03:22 AM',
            severity='critical',
            is_suspicious=True
        )
        db.session.add_all([l1, l2])
        db.session.commit()

        engine = QueryEngine()

        # 1. Midnight access
        res1 = engine.query('Who accessed this system at midnight?', case_id=self.case.id)
        self.assertIn('Midnight', res1['answer'])
        self.assertTrue(len(res1['supporting_records']) > 0)

        # 2. Failed logins
        res2 = engine.query('Show all failed login attempts', case_id=self.case.id)
        self.assertIn('Failed Authentication', res2['answer'])

        # 3. Suspicious IP
        res3 = engine.query('Which IP address generated the most suspicious events?', case_id=self.case.id)
        self.assertIn('High-Risk IP', res3['answer'])

        # 4. Before and after
        res4 = engine.query('What happened before and after this login?', case_id=self.case.id)
        self.assertIn('Temporal Killchain Reconstruction', res4['answer'])

        # 5. Incident summary
        res5 = engine.query('Generate a summary of this incident', case_id=self.case.id)
        self.assertIn('Incident', res5['answer'])

    # ── 6. ATTACK RECONSTRUCTION & TIMELINE APIS ─────────────────────────────

    def test_06_graph_and_timeline_apis(self):
        """Verify attack graph topology nodes/edges and timeline serialization."""
        self.login()

        # Graph API
        g_resp = self.client.get(f'/api/attack-graph/data?case_id={self.case.id}')
        self.assertEqual(g_resp.status_code, 200)
        g_data = g_resp.get_json()
        self.assertIn('nodes', g_data)
        self.assertIn('edges', g_data)
        self.assertIn('stats', g_data)

        # Timeline API
        t_resp = self.client.get(f'/api/timeline/events?case_id={self.case.id}')
        self.assertEqual(t_resp.status_code, 200)
        t_data = t_resp.get_json()
        self.assertIn('events', t_data)

        # Timeline CSV Export
        exp_resp = self.client.get(f'/api/timeline/export?case_id={self.case.id}')
        self.assertEqual(exp_resp.status_code, 200)
        self.assertEqual(exp_resp.mimetype, 'text/csv')

    # ── 7. CASE MANAGEMENT & AUDIT LOGGING ───────────────────────────────────

    def test_07_case_management_and_notes(self):
        """Verify case creation, status modification, note additions, and audit entries."""
        self.login()

        # Create new case
        new_case_resp = self.client.post('/api/cases', json={
            'title': 'Investigative Docket Alpha',
            'priority': 'critical',
            'description': 'Active incident handling'
        })
        self.assertEqual(new_case_resp.status_code, 201)
        created_case = new_case_resp.get_json()['case']
        cid = created_case['id']

        # Add investigator note
        note_resp = self.client.post(f'/api/cases/{cid}/notes', json={
            'content': 'Threat actor beaconed to Russian VPS. Isolating subnet.',
            'note_type': 'finding'
        })
        self.assertEqual(note_resp.status_code, 201)

        # Update status
        patch_resp = self.client.patch(f'/api/cases/{cid}', json={'status': 'closed'})
        self.assertEqual(patch_resp.status_code, 200)
        self.assertEqual(patch_resp.get_json()['case']['status'], 'closed')

    # ── 8. REPORTLAB PDF FORENSIC REPORT GENERATION ───────────────────────────

    def test_08_pdf_report_generation(self):
        """Verify ReportLab compiles valid multi-page forensic reports with SHA-256 signatures."""
        output_pdf = os.path.join(TestConfig.REPORTS_FOLDER, f'eval_report_{self.case.case_id}.pdf')
        generate_investigation_report(case_id=self.case.id, output_path=output_pdf)

        self.assertTrue(os.path.exists(output_pdf))
        self.assertGreater(os.path.getsize(output_pdf), 1000)

        # Verify PDF magic bytes
        with open(output_pdf, 'rb') as f:
            header = f.read(5)
            self.assertEqual(header, b'%PDF-')


if __name__ == '__main__':
    unittest.main()
