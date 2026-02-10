# Archestra Sentinel

**Archestra Sentinel** is a governance and risk-control system for AI agents and MCP-based runtimes.  
It acts as a **sentinel layer** between agent execution and infrastructure, providing discovery, policy enforcement, and audit-grade observability.

This repository is structured as a **platform**, not a demo app.

---

## 🎯 Problem Statement

As AI agents gain access to tools, databases, and external systems, organizations lose visibility and control over:
- What agents can access
- Which tools are safe vs shadow tools
- How to enforce kill-switches and policies in real time
- How to audit agent behavior after execution

**Sentinel solves this by introducing a centralized control plane for agent governance.**

---

## 🧠 What Sentinel Does

- **Agent & Tool Discovery**  
  Detects connected MCP servers, tools, and agent capabilities.

- **Risk Scoring & Policy Mapping**  
  Evaluates tools and agents against governance rules and trust thresholds.

- **Kill Switch & Enforcement**  
  Allows immediate disabling of risky tools or agent actions.

- **Audit Logs & Observability**  
  Maintains traceable execution logs for compliance and review.

- **Frontend Cockpit**  
  A high-signal dashboard for security, governance, and executive visibility.

---

## 🏗️ Architecture Overview

This is a **mono-repo** organized by responsibility:
archestra-sentinel/
├── sentinel-frontend/ # Governance & observability cockpit (React)
├── sentinel-backend/ # Core risk engine & policy enforcement (FastAPI)
├── mcp-runtime/ # MCP server registry & execution layer
├── platform/ # Archestra integration & orchestration
└── .github/ # CI/CD and automation

Each module is independently evolvable but designed to work as a single system.

---

## 🖥️ Sentinel Frontend (Cockpit)

Located in `sentinel-frontend/`

- Built as a **control cockpit**, not a marketing UI
- Focused on:
  - Discovery dashboards
  - Governance actions
  - Audit logs
  - Executive summaries
- Talks directly to `sentinel-backend` via typed APIs

The frontend is intentionally modular and can be replaced or extended without affecting backend enforcement logic.

---

## 🧩 Sentinel Backend (Brain)

Located in `sentinel-backend/`

Responsibilities include:
- Risk scoring
- Policy enforcement
- Kill-switch execution
- Audit persistence
- Integration with Archestra guardrails

This service is the **source of truth** for governance decisions.

---

## 🔌 MCP Runtime Layer

Located in `mcp-runtime/`

- Maintains registry of MCP servers
- Separates **verified** vs **sandbox** tools
- Acts as the execution boundary for potentially dangerous actions

This layer enables Sentinel to reason about *what could happen*, not just *what did happen*.

---

## 🚀 Getting Started (Local)

> Minimal setup for development

```bash
# Frontend
cd sentinel-frontend
npm install
npm run dev

# Backend (example)
cd sentinel-backend
pip install -r requirements.txt
uvicorn main:app --reload
