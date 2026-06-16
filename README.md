# VulnSight - Security Auditing & Vulnerability Management Platform

VulnSight is an asynchronous web-based security auditing framework designed to scan target websites for common vulnerabilities. The platform categorizes identified threats, generates professional PDF assessment reports, and leverages AI models to provide structured remediation guidance and secure coding examples.

This version has been re-engineered with a fully decoupled frontend-backend architecture, eliminating synchronous request bottlenecks by moving scans to an asynchronous queue (Celery + Redis) and executing security scanners (Nmap, Nikto, and OWASP ZAP) inside ephemeral Docker containers.

---

# 🚀 Features

## Asynchronous Scan Processing

* Uses Celery and Redis to execute long-running scans in the background.
* Prevents HTTP request blocking.
* Real-time scan status tracking (`Pending → Running → Completed/Failed`).

## Containerized Security Scanners

* No local installation of Nmap, Nikto, or OWASP ZAP required.
* All scanners execute within isolated Docker containers.
* Simplifies deployment and environment setup.

## Docker Networking Support

* Automatically converts `localhost` and `127.0.0.1` targets to `host.docker.internal`.
* Enables containers to access services running on the host machine.

## Custom Vulnerability Detection

* BeautifulSoup-based crawlers for:

  * Reflected Cross-Site Scripting (XSS)
  * SQL Injection (SQLi)
* Automated form discovery and payload testing.

## AI-Powered Remediation

* Integrates with:

  * Google Gemini (`gemini-1.5-flash`)
  * OpenAI (`gpt-3.5-turbo`)
* Generates:

  * Vulnerability explanations
  * Remediation recommendations
  * Secure coding examples
* Includes a rule-based fallback remediation engine when API keys are unavailable.

## Professional PDF Reporting

* Generates security assessment reports using ReportLab.
* Includes:

  * Executive summaries
  * Severity breakdowns
  * Evidence logs
  * AI-generated remediation guidance

## Modern User Dashboard

* React-based single-page application.
* JWT authentication and authorization.
* Live scan monitoring and report downloads.

---

# 🛠 Technology Stack

## Frontend

| Technology          | Purpose           |
| ------------------- | ----------------- |
| React 19            | User Interface    |
| Vite                | Build Tool        |
| Tailwind CSS        | Styling           |
| React Router DOM v7 | Routing           |
| Axios               | API Communication |
| JWT                 | Authentication    |

## Backend

| Technology            | Purpose                    |
| --------------------- | -------------------------- |
| Django                | Backend Framework          |
| Django REST Framework | REST APIs                  |
| PostgreSQL            | Database                   |
| Celery                | Background Task Processing |
| Redis                 | Message Broker             |
| Docker                | Scanner Isolation          |
| ReportLab             | PDF Generation             |
| Gemini API            | AI Remediation             |
| OpenAI API            | AI Remediation             |

---

# 📂 Project Structure

```text
vulnsight/
├── client/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── utils/
│   │   └── App.jsx
│   └── vite.config.js
│
└── server/
    ├── core/
    ├── requirements.txt
    ├── .env.example
    └── apps/
        ├── authentication/
        ├── scans/
        ├── vulnerabilities/
        ├── ai_remediation/
        └── reports/
```

---

# ⚙️ System Architecture

```text
[React Client]
       │
       ▼
[Django REST API]
       │
       ▼
[Create Scan Request]
       │
       ▼
[Celery Queue + Redis Broker]
       │
       ▼
[Celery Worker]
       │
       ├── Custom XSS Scanner
       ├── Custom SQLi Scanner
       ├── Dockerized Nmap
       ├── Dockerized Nikto
       └── Dockerized OWASP ZAP
       │
       ▼
[Vulnerability Findings]
       │
       ▼
[Gemini / OpenAI]
       │
       ▼
[Remediation Generation]
       │
       ▼
[PostgreSQL Storage]
       │
       ▼
[PDF Report Generation]
       │
       ▼
[React Dashboard]
```

---

# 🔄 Scan Workflow

```text
User Initiates Scan
        │
        ▼
Create Scan Record (Pending)
        │
        ▼
Enqueue Celery Task
        │
        ▼
Worker Starts Scan (Running)
        │
        ├── XSS Detection
        ├── SQLi Detection
        ├── Nmap Scan
        ├── Nikto Scan
        └── OWASP ZAP Scan
        │
        ▼
Store Findings
        │
        ▼
Generate AI Remediation
        │
        ▼
Generate PDF Report
        │
        ▼
Update Status (Completed)
        │
        ▼
React UI Displays Results
```

---

# 🔒 REST API

## Authentication

**Base URL:** `/api/auth`

| Method | Endpoint    | Description                             |
| ------ | ----------- | --------------------------------------- |
| POST   | `/register` | Register a new user                     |
| POST   | `/login`    | Authenticate user and return JWT tokens |
| GET    | `/me`       | Retrieve authenticated user profile     |

---

## Security Scans

**Base URL:** `/api/scans`

| Method | Endpoint | Description                         |
| ------ | -------- | ----------------------------------- |
| POST   | `/`      | Create a new scan job               |
| GET    | `/`      | Retrieve scan history               |
| GET    | `/<id>`  | Retrieve scan details               |
| DELETE | `/<id>`  | Delete scan and associated findings |

---

## Reports

**Base URL:** `/api/reports`

| Method | Endpoint          | Description                                   |
| ------ | ----------------- | --------------------------------------------- |
| GET    | `/scans/<id>/pdf` | Download generated security assessment report |

---

# 🔐 Security Scanners

| Scanner             | Purpose                                     |
| ------------------- | ------------------------------------------- |
| Custom XSS Scanner  | Reflected XSS Detection                     |
| Custom SQLi Scanner | SQL Injection Detection                     |
| Nmap                | Port & Service Discovery                    |
| Nikto               | Web Server Vulnerability Assessment         |
| OWASP ZAP           | Dynamic Application Security Testing (DAST) |

---

# 📊 Key Highlights

* Asynchronous scan execution using Celery and Redis.
* Containerized security scanners with Docker.
* AI-generated remediation guidance and secure coding examples.
* Automated PDF security assessment reports.
* JWT-based authentication and authorization.
* React + Django full-stack architecture.
* PostgreSQL-backed vulnerability management.
* Custom XSS and SQL Injection detection engine.

---

# 🎯 Future Enhancements

* Real-time scan progress using WebSockets.
* Scheduled and recurring scans.
* CVE database integration.
* Multi-user team collaboration.
* Scan comparison and historical trend analysis.
* Email notifications for completed scans.

---


