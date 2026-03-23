# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ Current |

## Reporting a Vulnerability

If you discover a security vulnerability in PentAgent itself (not in a target you are testing), please report it responsibly.

### How to Report

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email: [your-security-email@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if applicable)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix/Patch**: Within 30 days for confirmed vulnerabilities
- **Disclosure**: Coordinated disclosure after fix is released

## Scope

### In Scope

- Vulnerabilities in PentAgent's code that could lead to:
  - Unauthorized command execution beyond the intended target
  - Data exfiltration from the host system
  - Privilege escalation
  - Bypass of scope-limiting controls

### Out of Scope

- Vulnerabilities in third-party tools (nmap, sqlmap, nuclei, etc.)
- Vulnerabilities in Ollama or the LLM model
- Issues related to the target system being tested (that's the tool's purpose)
- Social engineering attacks

## Responsible Use

PentAgent includes terminal access capabilities by design. This is an intended feature for authorized penetration testing. The tool includes:

- Domain scope warnings when commands don't reference the target
- Built-in scope checks for HTTP-based tools
- Authorization prompts at startup

Users are solely responsible for ensuring they have proper authorization before using this tool against any target.

## Security Design Decisions

1. **Local-only LLM**: No data is sent to cloud APIs. All inference runs locally via Ollama.
2. **Explicit client initialization**: The Ollama client connects to `127.0.0.1:11434` explicitly to avoid DNS resolution issues.
3. **Command logging**: All terminal commands are logged to `audit_output/scan_logs/` for audit trail purposes.
4. **Checkpoint persistence**: Session state is saved locally and never transmitted.
