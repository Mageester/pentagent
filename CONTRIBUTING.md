# Contributing to PentAgent

Thank you for your interest in contributing. This document provides guidelines for contributing to the project.

## Code of Conduct

- This is a security tool for **authorized testing only**
- Do not submit code that facilitates unauthorized access
- Do not include exploit payloads or offensive toolkits
- Keep contributions focused on defensive security validation

## How to Contribute

### Reporting Bugs

1. Check existing issues first
2. Include: Python version, OS, Ollama version, error output
3. Include steps to reproduce

### Feature Requests

1. Open an issue with the `enhancement` label
2. Describe the use case and expected behavior
3. Explain how it fits within authorized security testing

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Follow the existing code style
4. Test your changes locally
5. Submit a PR with a clear description

## Development Setup

```powershell
git clone https://github.com/youruser/pentagent.git
cd pentagent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt  # or let agent.py self-bootstrap
```

## Code Style

- Python 3.9+ with type hints
- Functions follow the `tool_*` naming convention for agent tools
- Security check modules in `security_tools.py`
- Rich console output for all user-facing messages
- `ToolResult` dataclass for all tool return values

## Architecture Guidelines

- **Tools are pure functions** that return `ToolResult` objects
- **Security tools** go in `security_tools.py` and return `{ok, findings, data}` dicts
- **Agent tools** in `agent.py` wrap security tools and record findings to state
- **Workspace and gateway state** belong in `workspace.py` and `gateway.py`
- **Browser dashboard logic** belongs in `dashboard.py`
- **File-backed capability packs** live under `skills/` and `workspace/agents/<agent_id>/skills/`
- **The LLM orchestration layer** should not contain business logic
- **All subprocess calls** must be Windows-safe (no bash-isms)

## What We Accept

- ✅ New built-in security checks
- ✅ Improved reporting and output formats
- ✅ Better LLM prompt engineering
- ✅ Performance and reliability improvements
- ✅ Documentation improvements
- ✅ Windows/cross-platform compatibility fixes

## What We Don't Accept

- ❌ Exploit payloads or weaponized code
- ❌ Features designed for unauthorized access
- ❌ Cloud/SaaS integrations that transmit target data
- ❌ Changes that remove authorization safeguards
