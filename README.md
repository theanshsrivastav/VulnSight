# VulnSight - Security Auditing & Vulnerability Management Platform

VulnSight is an asynchronous, web-based security auditing framework designed to scan target websites for common vulnerabilities. It categorizes identified threats, generates professional PDF assessment reports, and leverages AI models to provide structured remediation guidance and secure coding examples.

This version has been re-engineered from the ground up to utilize a strictly decoupled frontend-backend architecture, solving synchronous request-blocking bottlenecks by shifting scans to an asynchronous queue (Celery + Redis) and running security engines (Nmap, Nikto, OWASP ZAP) inside ephemeral Docker containers.

---

## 🚀 Key Features

- **Asynchronous Scan Queue**: Utilizes Celery and Redis to run long-running scans in the background. Web requests are unblocked instantly, and the UI polls for scan status (`pending` -> `running` -> `completed`/`failed`).
- **Zero Local Executable Installs**: Shipped completely with Docker-run wrappers. All external security scanners run inside Docker containers, eliminating host binary requirements (`nmap.exe` or `nikto` command setups).
- **Docker Networking Translation**: Targets pointing to local loopbacks (`localhost` or `127.0.0.1`) are automatically translated to `host.docker.internal` so containers can scan host services.
- **Custom Auditing Scanners**: Custom BeautifulSoup-based web crawlers for identifying Reflected Cross-Site Scripting (XSS) and SQL Injection (SQLi) vulnerabilities in HTML forms.
- **AI Remediation Suggestions**: Automatically feeds discovered vulnerabilities to Google Gemini (`gemini-1.5-flash`) or OpenAI (`gpt-3.5-turbo`) to produce structured security fixes. Implements a rules-based fallback engine to generate simulated remediation if API keys are absent.
- **One-Click PDF Reports**: Generates dynamic, styling-customized PDF audit reports using ReportLab, displaying executive summary matrices, threat severity charts, evidence logs, and AI secure coding blocks.
- **Modern Dashboard**: A clean React + Tailwind CSS single-page interface with live scanner tracking and JWT-based authentication.

---

## 🛠️ Technology Stack

### Frontend
- **Framework**: React 19, Vite
- **Styling**: Tailwind CSS
- **Routing**: React Router DOM v7
- **HTTP Client**: Axios (configured with automated JWT authorization interceptors)

### Backend
- **Framework**: Django, Django REST Framework (DRF)
- **Database**: PostgreSQL (native Django ORM integration)
- **Task Worker & Broker**: Celery, Redis
- **Security Scanners**: Ephemeral Docker images (`sullo/nikto`, `instrumentisto/nmap`, `owasp/zap2docker-stable`)
- **Document Generation**: ReportLab
- **AI Integrations**: Google Generative AI (Gemini SDK), OpenAI SDK

---

## 📂 Project Directory Structure

```text
vulnsight-2.0/
├── client/                     # React + Vite Frontend App
│   ├── src/
│   │   ├── components/         # Reusable UI Components
│   │   ├── pages/              # Dashboard, Login, Register, ScanDetails
│   │   ├── utils/              # API Client (Axios), AuthContext
│   │   └── App.jsx             # React Routes
│   └── vite.config.js          # Port 5000 & Proxy Configurations
│
└── server/                     # Django REST Backend
    ├── core/                   # Django Settings, URLs, and Celery app setup
    ├── requirements.txt        # Backend dependencies list
    ├── .env.example            # Environment configuration template
    └── apps/                   # Django Modular Applications
        ├── authentication/     # Custom User & Simple JWT endpoints
        ├── scans/              # Scans scheduling, tasks, & Docker integrations
        ├── vulnerabilities/    # Vulnerability databases & findings models
        ├── ai_remediation/     # Gemini/OpenAI integrations & Fallbacks
        └── reports/            # Dynamically compiled ReportLab PDFs




**## System Architecture and Scan Workflow**

[User requests scan from React UI] 
       │
       ▼
[Django REST Endpoint: POST /api/scans] ──► (Saves Scan as "Pending")
       │
       ▼
[Enqueue Asynchronous Celery Task]
       │
       ▼ [Celery Worker starts task]
(Updates Scan status to "Running")
       │
       ├─► [Runs Custom XSS/SQLi BS4 Crawlers]
       ├─► [Spawns Docker: instrumentisto/nmap (Parses XML)]
       ├─► [Spawns Docker: sullo/nikto (Parses Stdout)]
       └─► [Queries Docker: owasp/zap2docker-stable (API Calls)]
       │
       ▼ [Vulnerabilities Found]
(Pipes vulnerability data to Gemini/OpenAI API) ──► (Generates Fix Guides)
       │
       ▼
(Updates Scan status to "Completed" + saves AI suggestions)
       │
       ▼
[React UI polls endpoint & renders complete details + PDF download button]




**## 🔒 API Endpoints**
Authentication /api/auth/
- POST /api/auth/register - Register a new user. Returns JWT credentials.
- POST /api/auth/login - Authenticate user. Returns JWT credentials.
- GET /api/auth/me - Retrieve current profile details.

Security Scans /api/scans/
- POST /api/scans - Create a new scan job (triggers Celery background task).
- GET /api/scans - List all scan history for the authenticated user.
- GET /api/scans/<id> - Retrieve details of a specific scan, including vulnerabilities and AI fixes.
- DELETE /api/scans/<id> - Delete a scan job and its findings database cascades.

Reports /api/reports/
- GET /api/reports/scans/<id>/pdf - Stream and download dynamically-generated PDF security report.
