# 🔐 CYBERTRACE AI
## AI-Powered Cybercrime Investigation & Digital Forensics Platform

> **⚠️ DISCLAIMER:** This is a demonstration application for authorized forensic investigation workflows only. All sample data is **fictional and simulated**. Do not use this tool for unauthorized scanning, surveillance, or real-world attack attribution.

---

## 📋 Features

| Module | Description |
|--------|-------------|
| 🔐 **Authentication** | Secure login with password hashing, session management, role-based access |
| 📊 **Dashboard** | Live stats, threat severity chart, event trends, recent activity feed |
| 🗂️ **Evidence Management** | Upload CSV/JSON/TXT logs, SHA-256 hash verification, integrity checking |
| 📋 **Log Analysis** | Parse & normalize logs, filter/search, event classification, pagination |
| 🤖 **AI Assistant** | Rule-based NL query engine grounded in uploaded evidence (no API key needed) |
| 🕐 **Incident Timeline** | Chronological event view grouped by date with severity indicators |
| 🕸️ **Attack Graph** | Interactive canvas graph linking IPs, users, events (pan/zoom) |
| 🛡️ **Threat Detection** | Brute force, off-hours access, privilege escalation, lateral movement |
| 📁 **Case Management** | Full CRUD case workflow with notes, priorities, investigator assignment |
| 📄 **PDF Reports** | ReportLab-generated forensic reports with timelines, hashes, findings |

---

## 🚀 Quick Start (Windows / VS Code)

### Prerequisites
- **Python 3.10+** — [python.org](https://python.org/downloads)
- **pip** (included with Python)
- **VS Code** (recommended) with Python extension

### Step 1 — Open project in VS Code
Open VS Code → **File → Open Folder** → select `cybertrace-ai` directory.
Open terminal: **Ctrl + `**

### Step 2 — Create virtual environment
```powershell
python -m venv venv
venv\Scripts\activate
```

### Step 3 — Install dependencies
```powershell
pip install -r requirements.txt
```

### Step 4 — Configure environment
```powershell
copy .env.example .env
```
Edit `.env` and set a `SECRET_KEY`. Defaults work for local dev.

### Step 5 — Initialize database & sample data
```powershell
python init_db.py
```

**Demo login credentials:**

| Role | Email | Password |
|------|-------|----------|
| Admin | `admin@cybertrace.ai` | `CyberTrace2024!` |
| Investigator | `investigator@cybertrace.ai` | `Invest2024!` |
| Analyst | `analyst@cybertrace.ai` | `Analyst2024!` |

### Step 6 — Run the application
```powershell
python run.py
```
Open browser: **http://localhost:5000**

---

## 📁 Project Structure

```
cybertrace-ai/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── config.py                # Configuration
│   ├── models.py                # SQLAlchemy models
│   ├── auth/routes.py           # Login / logout / profile
│   ├── dashboard/routes.py      # Dashboard stats & activity
│   ├── evidence/routes.py       # Evidence upload & verification
│   ├── logs/routes.py           # Log analysis & filtering
│   ├── ai_assistant/routes.py   # AI chat endpoint
│   ├── timeline/routes.py       # Incident timeline
│   ├── attack_graph/routes.py   # Attack reconstruction graph data
│   ├── threats/routes.py        # Threat detection & alerts
│   ├── cases/routes.py          # Case management & notes
│   ├── reports/routes.py        # PDF report generation
│   └── utils/
│       ├── hashing.py           # SHA-256 computation & verification
│       ├── log_parser.py        # CSV / JSON / TXT parser
│       ├── threat_detector.py   # Detection algorithms
│       ├── ai_engine.py         # Rule-based NL query engine
│       ├── pdf_generator.py     # ReportLab PDF generation
│       └── audit.py             # Audit trail helper
├── templates/                   # Jinja2 HTML templates
├── static/css/style.css         # Dark SOC dashboard stylesheet
├── static/js/                   # JavaScript modules
├── sample_data/                 # Created by init_db.py (simulated)
├── uploads/                     # Evidence file storage (auto-created)
├── reports/                     # Generated PDF reports (auto-created)
├── init_db.py                   # DB initialization & sample seeding
├── run.py                       # Flask entry point
├── requirements.txt             # Python dependencies
└── .env.example                 # Environment template
```

---

## 🛡️ Security Features

- Password hashing via `werkzeug.security` (PBKDF2-SHA256)
- Session management via Flask-Login
- CSRF protection via Flask-WTF
- File upload validation (allowed extensions + 32 MB size limit)
- Path traversal protection via `secure_filename`
- SHA-256 integrity verification on ingestion and on-demand
- Comprehensive audit logging of all investigator actions
- Files are never executed — only parsed

---

## 🤖 AI Assistant (Dual Engine)

The AI Assistant can run in 100% offline rule-based mode or with LLM assistance:
- **No-API Demo Mode (Default):** Zero setup required. Runs completely locally without third-party APIs. Natural language queries are grounded strictly in the evidence files and indexed logs with citations and timestamps.
- **Gemini API Mode:** Set `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) and `AI_MODE=gemini` in `.env`.
- **OpenAI API Mode:** Set `OPENAI_API_KEY` and `AI_MODE=openai` in `.env`.

**Example Questions:**
- *"Who accessed this system at midnight?"*
- *"Show all failed login attempts"*
- *"Which IP address generated the most suspicious events?"*
- *"What happened before and after this login?"*
- *"Generate a summary of this incident"*
- *"List all privilege escalation events"*

---

## 🧪 Running Automated Tests

Run the full end-to-end integration test suite:
```powershell
python -m unittest tests/test_cybertrace.py
```
This tests:
1. Authentication flow (Login / Logout / CSRF / Session)
2. Dashboard metrics and event trend APIs
3. Evidence upload, SHA-256 hash calculation, and integrity verification
4. Log parsing, normalization, and filtering
5. AI investigation engine intent matching and grounded responses
6. Threat detection engine (brute force, off-hours, privilege escalation)
7. Attack reconstruction graph node/edge topology
8. Court-ready PDF report generation (ReportLab)

---

## ☁️ Deploying to Vercel

CYBERTRACE AI is pre-configured with `vercel.json` and `api/index.py` for seamless deployment to Vercel Serverless Functions.

### Method 1: Deploy via GitHub (Recommended)

1. Commit and push your code to your GitHub repository:
   ```powershell
   git add .
   git commit -m "Configure Vercel serverless deployment"
   git push origin main
   ```
2. Go to [vercel.com/new](https://vercel.com/new) and log in with your GitHub account.
3. Select your repository (**CyberTracker**).
4. In the **Configure Project** screen:
   - **Framework Preset:** *Other* (detected automatically via `vercel.json`)
   - **Root Directory:** `./`
   - In **Environment Variables**, add:
     - `SECRET_KEY` = `<any-random-32-char-string>`
     - `AI_MODE` = `rule_based` (or `gemini` / `openai`)
     - `GEMINI_API_KEY` or `OPENAI_API_KEY` (optional)
5. Click **Deploy**. Vercel will build and deploy your app in ~1 minute.

### Method 2: Deploy via Vercel CLI

1. Install Vercel CLI globally (if not already installed):
   ```powershell
   npm install -g vercel
   ```
2. From the project directory, log in and deploy:
   ```powershell
   vercel login
   vercel
   ```
3. To deploy directly to production:
   ```powershell
   vercel --prod
   ```

> **Note on Serverless Storage:** In Vercel's serverless environment, files are stored in the writable `/tmp` directory and the database auto-seeds on initial cold start. For permanent database persistence across cold boots in production, set `DATABASE_URL` in your Vercel Project Settings to a hosted PostgreSQL/MySQL instance (such as Supabase, Neon, or PlanetScale).

---

## 📊 Supported Log Formats

| Format | Description |
|--------|-------------|
| CSV | Auth logs: timestamp, source_ip, username, event_type, status columns |
| JSON | System events: timestamp, process, event, severity fields |
| TXT | Syslog-style: `Nov 15 02:15:03 sshd: Failed password for admin from ...` |

---

## 🔧 Troubleshooting

**`ModuleNotFoundError: No module named 'flask'`**
```powershell
venv\Scripts\activate
pip install -r requirements.txt
```

**`sqlite3.OperationalError: no such table`**
```powershell
python init_db.py
```

**Port 5000 already in use** — edit `run.py` and change `port=5000` to `port=5001`

**PDF generation fails** — `pip install reportlab --upgrade`

---

*Built with Flask · SQLAlchemy · Chart.js · ReportLab · Canvas API*
