# PENTAGENT

**Autonomous penetration testing and security validation framework for authorized environments.**

> Local LLM-driven security assessment agent that performs comprehensive reconnaissance, vulnerability scanning, and reporting — fully automated, fully offline.

---

## Overview

PentAgent is a self-bootstrapping, autonomous penetration testing framework designed for authorized security assessments. It uses a local large language model via Ollama to orchestrate multi-phase security testing without cloud dependencies or API keys.

The agent operates as an intelligent decision loop: it runs reconnaissance, analyzes results, decides what to test next, executes security tools, and produces structured reports — all without human intervention after target specification.

**This tool is intended exclusively for authorized penetration testing and security validation of systems you own or have explicit written permission to test.**

At launch you choose the target, mode, scan profile, model, and an optional operator mission. The agent auto-pulls the selected Ollama model if it is missing, prefers Kali/Athena WSL tooling when available, and keeps going when optional tools fail so it can pivot instead of stalling.

---

## Key Capabilities

| Capability | Description |
|---|---|
| **LLM-Driven Orchestration** | Your chosen Ollama model decides what to scan, what tools to run, and when the assessment is complete |
| **Full Terminal Access** | The agent can execute any shell command — nmap, sqlmap, nuclei, or custom scripts |
| **Self-Bootstrapping** | Auto-installs Python dependencies, Playwright, and can install security tools via winget/pip |
| **8 Built-In Security Checks** | SSL/TLS, cookies, sensitive paths, CORS, mixed content, email security, info disclosure, security headers (with A–F grading) |
| **Web Crawling & Analysis** | Full site mapping, metadata extraction, broken link detection, redirect chain analysis |
| **Browser Rendering** | Playwright-based screenshots and JS-rendered DOM extraction |
| **Lighthouse Integration** | Performance, accessibility, SEO, and best practices scoring |
| **Persistent State** | Checkpoint/resume support — interrupt and continue assessments |
| **Attack-Graph Memory** | Tracks discovered surfaces, findings, confidence, and pivots across the run |
| **Operator Mission Setting** | Set a broad custom mission at launch and let the agent choose the best authorized pivots |
| **Model Selection at Startup** | Pick the Ollama tag you want, and the agent auto-pulls it if it is missing |
| **WSL Tool Routing** | Routes Linux recon and exploitation tools to the best available Kali/Athena WSL distro |
| **Rich Terminal UI** | ASCII art banner, live progress, structured tool output, dashboards |
| **Structured Reporting** | Machine-readable JSON + markdown + HTML reports with detailed findings |
| **Release Notes UI** | Polished browser-readable changelog page with release highlights and operator guidance |

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Interactive Startup                 │
│    Target domain · Scan profile · Authorization  │
├─────────────────────────────────────────────────┤
│           Self-Bootstrap Engine                  │
│   Packages · Playwright · Tools · Ollama/Model   │
├─────────────────────────────────────────────────┤
│         Deterministic Kickoff Phase              │
│  Recon: crawl, robots, sitemap, batch fetch      │
│  Security: SSL, headers, cookies, paths, CORS,   │
│           email, info disclosure                 │
├─────────────────────────────────────────────────┤
│         LLM-Driven Assessment Loop               │
│  ┌───────────┐    ┌──────────────┐               │
│  │  Qwen3    │───>│  Tool        │               │
│  │  Decision │    │  Execution   │               │
│  │  Engine   │<───│  + Terminal  │               │
│  └───────────┘    └──────────────┘               │
│         │                                        │
│  ┌──────┴───────┐                                │
│  │   Memory     │  Periodic summarization        │
│  │   Manager    │  for context management         │
│  └──────────────┘                                │
├─────────────────────────────────────────────────┤
│              Report Generation                   │
│         JSON · Markdown · Screenshots            │
│         Lighthouse · Scan Logs                   │
└─────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- **Python 3.9+**
- **Ollama** — [Download](https://ollama.com/download)
- **Node.js** (optional) — enables Lighthouse auditing
- **nmap** (optional) — enables port/service scanning

### Quick Start

```powershell
git clone https://github.com/youruser/pentagent.git
cd pentagent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python agent.py
```

The script auto-installs all Python dependencies on first run. No manual `pip install` required.

### Model Setup

```powershell
# Ensure Ollama is running
ollama serve

# The agent can auto-pull the selected model if missing, or manually:
ollama pull qwen3-coder:30b
```

Recommended default for strongest reasoning is `qwen3-coder:30b`, but you can choose any Ollama model tag at startup or with `--model`.
The agent auto-pulls the selected model if it is missing.

---

## Usage

### Interactive Mode (Recommended)

```powershell
python agent.py
```

Presents an interactive menu:
- Target or subnet input
- Mode selection (web / network)
- Model selection
- Scan profile selection (quick / standard / deep)
- Optional operator mission for broad authorized work you want prioritized
- Resume/fresh session choice

### CLI Mode

```powershell
python agent.py example.com              # target specific domain
python agent.py example.com --fresh      # start fresh (ignore checkpoint)
python agent.py --resume                 # resume previous session
python agent.py example.com --mission "find IDORs in profile endpoints; map admin panels"
python agent.py example.com --objective "map attack surface and validate auth/session flaws"
```

You can also enter a mission interactively. Separate multiple mission items with semicolons.
The startup parser accepts `--mission`, `--objective`, or the legacy `--task` alias.

### Runtime Notes

- `web` mode is for domains and URLs; `network` mode is for CIDRs or `auto`.
- Public DNS recon is used for public domains; localhost and lab-style targets skip that noise and go straight to direct enumeration.
- Optional tool failures are logged and the run continues, so the agent can pivot instead of dying on a missing binary.
- Lighthouse is optional and depends on a Chromium-capable browser being available on the host.

### Scan Profiles

| Profile | Max Steps | Description |
|---|---|---|
| `quick` | 20 | Fast reconnaissance and basic security checks |
| `standard` | 50 | Comprehensive assessment with vulnerability testing |
| `deep` | 100 | Exhaustive testing with extended tool usage |

---

## Output Artifacts

All output is written to `audit_output/`:

```
audit_output/
├── checkpoint.json          # Session state (resume support)
├── audit_report.json        # Machine-readable full report
├── audit_summary.md         # LLM-generated executive summary
├── audit_summary.html       # Browser-friendly detailed report
├── screenshots/             # Playwright full-page captures
├── lighthouse/              # Lighthouse JSON reports
└── scan_logs/               # Terminal command output logs
```

The repository root also includes `RELEASE_NOTES.html`, a browser-friendly release/changelog page that summarizes the latest operator-focused changes.

---

## Built-In Security Checks

| Check | What It Tests |
|---|---|
| SSL/TLS Analysis | Certificate validity, expiration, protocol version, cipher strength |
| Security Headers | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy (A–F grade) |
| Cookie Security | Secure, HttpOnly, SameSite attributes |
| Sensitive Path Exposure | .env, .git, .htpasswd, phpinfo.php, admin panels, backups |
| CORS Misconfiguration | Wildcard, reflected origin, null origin, credentials with wildcard |
| Email Security | SPF and DMARC DNS record validation |
| Information Disclosure | Server version headers, X-Powered-By, error page leakage |
| Mixed Content | HTTP resources loaded on HTTPS pages |

---

## Security & Authorization

> **⚠️ IMPORTANT: This tool is designed exclusively for authorized security testing.**

By using this software, you acknowledge and agree that:

1. You have **explicit written authorization** to test the target system
2. You will **only target systems you own** or have permission to assess
3. You understand that unauthorized access to computer systems is **illegal** in most jurisdictions
4. The authors and contributors are **not responsible** for misuse of this tool
5. You will comply with all applicable **local, state, national, and international laws**

This tool is intended for:
- Professional penetration testers with client authorization
- Security teams assessing their own infrastructure
- Red team / blue team exercises within authorized scope
- Compliance and security validation testing

---

## Use Cases

- **Internal Security Audits** — Validate your organization's web application security posture
- **Pre-Deployment Validation** — Test staging environments before production release
- **Compliance Checks** — Verify security headers, SSL configuration, and email security
- **Red Team Assessments** — Automated reconnaissance and vulnerability discovery phase
- **Developer Security Testing** — Catch security issues during development

---

## Not For

This tool is **not** intended for:

- ❌ Unauthorized access to systems you do not own
- ❌ Scanning targets without explicit written permission
- ❌ Bug bounty programs that prohibit automated scanning
- ❌ Denial of service testing without authorization
- ❌ Any activity that violates applicable law

---

## Roadmap

| Version | Milestone |
|---|---|
| `v0.1.0` | Core agent with built-in security checks and terminal access |
| `v0.2.0` | Enhanced reporting with CVSS scoring and remediation guidance |
| `v0.3.0` | Multi-target campaign support and scheduling |
| `v0.4.0` | Plugin architecture for custom security checks |
| `v0.5.0` | API endpoint testing (REST, GraphQL) |
| `v1.0.0` | Stable release with full documentation and test coverage |

---

## Tech Stack

- **Python 3.9+** — Core runtime
- **Ollama + chosen local model** — Local LLM inference (no cloud APIs)
- **Playwright** — Browser automation and rendering
- **BeautifulSoup + lxml** — HTML parsing
- **Rich** — Terminal UI
- **Lighthouse** — Performance and accessibility auditing (optional)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and responsible disclosure process.

## License

[MIT License](LICENSE) — See LICENSE file for details.

---

<p align="center">
  <sub>Built for authorized security professionals. Use responsibly.</sub>
</p>
