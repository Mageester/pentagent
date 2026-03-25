---
name: control-plane
category: platform
description: Launcher, workspace, provider, dashboard, and session control for the PentAgent platform.
tools: dashboard, onboard, doctor, skills, workspace, config
kind: pack
inputs: operator mission, workspace defaults, provider selection
outputs: runtime config, dashboard status, workspace layout
---

# Control Plane

This pack covers the platform shell around the pentest engine:
- workspace bootstrap
- provider/model selection
- launcher and dashboard behavior
- session persistence
- operational status

The pentest engine is one skill pack inside this platform.
