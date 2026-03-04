# ID-Networkers Combined Lab 2: The XML Gateway

A **chained-attack** security lab that combines two vulnerabilities into a single exploitation path:

| Phase | Vulnerability | Objective |
|-------|--------------|-----------|
| **1** | JWT "None" Algorithm Bypass | Escalate from `guest` → `admin` without knowing the secret key |
| **2** | XML External Entity (XXE) | Exfiltrate the contents of `/flag.txt` from the server |

---

## Learning Objectives

After completing this lab, students will be able to:

1. Explain how JSON Web Tokens (JWT) work and why accepting the `"none"` algorithm is dangerous.
2. Craft a forged JWT to bypass authentication and escalate privileges.
3. Understand how XML parsers process Document Type Definitions (DTDs) and external entities.
4. Exploit an XXE vulnerability to read arbitrary files from the server.
5. Recognize how **vulnerability chaining** amplifies overall risk.

---

## Project Structure

```
id-networkers-combined-02/
├── app/
│   ├── main.py          # FastAPI app — routes, JWT guard, vulnerable XML parser
│   ├── auth.py          # JWT creation & vulnerable verification logic
│   └── templates/
│       ├── login.html       # Authentication portal
│       ├── dashboard.html   # Admin panel with XML upload
│       └── result.html      # Parsed XML output
├── Dockerfile           # Python 3.11-slim, plants /flag.txt
├── docker-compose.yml   # Single-service container orchestration
├── requirements.txt     # Python dependencies
├── README.md            # ← You are here
└── SOLUTION.md          # Full walkthrough (SPOILERS!)
```

---

## Quick Start

### Prerequisites
- **Docker** and **Docker Compose** installed.

### Build & Run

```bash
cd id-networkers-combined-02
docker compose up --build -d
```

The lab will be available at **http://localhost:8000**.

### Stop

```bash
docker compose down
```

---

## 🕹️ How to Play

1. **Open** http://localhost:8000 in your browser.
2. **Log in** with the guest credentials shown on the login page (`guest` / `guest123`).
3. Notice that you receive an **"Access Denied"** message — the dashboard requires admin privileges.
4. Inspect the `session_token` cookie in your browser's Developer Tools.
5. **Phase 1:** Figure out how to modify the JWT to gain admin access.
6. **Phase 2:** Once inside the Admin Dashboard, use the XML upload feature to read `/flag.txt`.

> **Hint:** Pay attention to the "System Status" panel on the dashboard — it tells you something about the parser configuration.

---

## 🔧 Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI (Python 3.11) |
| JWT Library | python-jose |
| XML Parser | lxml (libxml2) |
| Templates | Jinja2 |
| Container | Docker |

---

## Disclaimer

This lab is designed **exclusively for educational purposes** in controlled environments. The vulnerabilities are **intentional**. Never deploy this application on a public network or use these techniques against systems without explicit authorization.

---

*ID-Networkers Security Training Labs — Authorized Use Only*
