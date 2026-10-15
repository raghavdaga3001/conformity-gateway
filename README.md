<div align="center">

# 🏛️ Conformity-Gateway

**High-Assurance AI Gateway, Governed Agent Runtime & EU AI Act Telemetry Engine**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-FF6F00)](https://langchain-ai.github.io/langgraph/)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Articles%2012%20%26%2015-blue)](https://artificialintelligenceact.eu/)
[![Docker Non-Root](https://img.shields.io/badge/Docker-UID%2010001-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

<p align="center">
  <a href="#-architectural-overview">Overview</a> •
  <a href="#-layered-defense-in-depth">Architecture</a> •
  <a href="#-eu-ai-act-compliance-matrix">Regulatory Matrix</a> •
  <a href="#-empirical-adversarial-benchmarks">Benchmarks</a> •
  <a href="#-quickstart">Quickstart</a>
</p>

</div>

---

## 📌 Architectural Overview

`Conformity-Gateway` is an enterprise inference gateway and governed agent execution runtime designed to enforce technical conformity under **EU AI Act Articles 12 & 15** and mitigate critical vulnerabilities identified in the **OWASP Top 10 for LLMs** (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, and LLM06 Excessive Agency / Confused Deputy).

Unlike passive wrapper frameworks, `Conformity-Gateway` implements **layered defense-in-depth**:
* **Ingress Latent Screener:** Extracts penultimate text embeddings and computes **Mahalanobis Distance** against baseline enterprise centroids. Adversarial injections, high-entropy exploits, and out-of-domain feature voids are rejected at the gateway prior to LLM invocation.
* **Governed LangGraph State Machine:** Executes bounded cyclical reasoning with Pydantic grammar constraints, document relevance grading, autonomous query reformulation, and pre-retrieval ChromaDB namespace isolation.
* **Zero-Trust Parameter Binding:** Tool schemas exposed to the model strip mutable identity parameters (`sender_id`, `tenant_id`); execution credentials are cryptographically injected from authenticated session claims at the gateway layer.
* **Egress Canary Tripwires:** High-entropy session sentinels (`CONF_CANARY_XXXX`) embedded into system prompts trip immediate circuit breakers if an extraction attempt breaches upstream controls.
* **Compliance Telemetry:** Background distribution tracking computing two-sample **Kolmogorov-Smirnov (KS)** tests and **Wasserstein Distance** alongside append-only SHA-256 cryptographic audit logs satisfying non-repudiation mandates.

---

## 🛡️ Layered Defense-in-Depth Architecture

```text
                                [ Inbound Client Request ]
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. INGRESS DEFENSE & LATENT OOD GATEWAY (FastAPI Middleware)                           │
│  ├── Delimiter Plane Separation (<untrusted_user_payload>)                             │
│  ├── Base64 / ROT13 Decoding & Breakout Pattern Inspection                             │
│  ├── Latent OOD Screener: MiniLM Mahalanobis distance against ID centroids             │
│  │     └── [Circuit Breaker]: Drops feature voids before LLM inference (Threshold=30.0)│
│  └── Dynamic Canary Injection: Ephemeral UUID sentinel injected into system prompt     │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ (Sanitized & Screened)
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 2. GOVERNED AGENTIC EXECUTION CORE (LangGraph State Machine)                           │
│  ├── Pre-Retrieval Partitioning: Tenant-isolated similarity search in ChromaDB         │
│  ├── Relevance Grading Node: Pydantic-constrained binary evaluation (GradeDocument)   │
│  ├── Autonomous Query Rewriting Node: Self-correcting loop on context starvation       │
│  ├── Zero-Trust Tool Execution: Parameter binding from session JWT (Confused Deputy)   │
│  └── Human-in-the-Loop (HITL) Gate: Asynchronous 2FA tickets for transfers > £5,000    │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ (Candidate Generation)
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. EGRESS ASSURANCE & CANARY TRIPWIRE                                                  │
│  ├── Grounding Evaluator: Pydantic factual verification against retrieved context      │
│  ├── Canary Tripwire Sentinel: Scans generation tokens for system prompt leakage       │
│  └── [Circuit Breaker]: Drops response and flags incident on sentinel detection        │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ (Verified Response)
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 4. TELEMETRY & COMPLIANCE ENGINE (EU AI Act Articles 12 & 15)                          │
│  ├── Statistical Drift Monitoring: 2-Sample KS-Test & Wasserstein Distance tracking   │
│  └── Immutable Event Logging: SHA-256 chained JSONL records for non-repudiation WORM   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚖️ EU AI Act Compliance Matrix

| Regulation Article | Statutory Requirement | Gateway Engineering Implementation |
| :--- | :--- | :--- |
| **Article 9** | Risk Management System | Continuous automated adversarial stress-testing via `benchmarks/redteam_suite.py`. |
| **Article 10** | Data Governance & Pre-Retrieval Isolation | Strict pre-retrieval vector filtering enforcing tenant isolation in ChromaDB. |
| **Article 12** | Automatic Event Logging | Append-only JSONL audit logs chained with SHA-256 cryptographic digests. |
| **Article 14** | Human Oversight (HITL) | Asynchronous 2FA authorization gates on transactional actions exceeding £5,000. |
| **Article 15** | Accuracy, Robustness & Cybersecurity | Latent Mahalanobis OOD screening, delimiter plane isolation, and canary sentinels. |

---

## 📊 Empirical Adversarial Benchmarks

Stress-tested against the identical adversarial permutation suite (Direct Probes, Persona Hijacks, Base64/ROT13 Ciphers, Delimiter Overrides) evaluated on open-weight runtimes (`llama3.2:1b`):

| Attack Mutation Strategy | Unprotected Baseline ASR | Protected Gateway ASR | Primary Defense Mechanism |
| :--- | :---: | :---: | :--- |
| **Direct Probe** | 100.00% | **0.00%** | Latent OOD Screener ($D_M > 30.0$) |
| **Persona Hijack** | 100.00% | **0.00%** | Latent OOD Screener & Delimiter Tags |
| **Base64 Obfuscation** | 100.00% | **0.00%** | Ingress Decoder & Latent OOD Screener |
| **ROT13 Obfuscation** | 100.00% | **0.00%** | Ingress Decoder & Latent OOD Screener |
| **Delimiter Override** | 100.00% | **0.00%** | Sanitizer Regex & Canary Tripwire |
| **Overall Vulnerability** | **100.00%** | **0.00%** | **Full Defense-in-Depth Coverage** |

---

## 🛠️ Quickstart

### 1. Installation & Environment Setup
```bash
git clone [https://github.com/](https://github.com/)<YOUR_USERNAME>/conformity-gateway.git
cd conformity-gateway

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Comprehensive Test Suite
```bash
pytest -v tests/
```

### 3. Run the Adversarial Red-Team Benchmark
```bash
python -m benchmarks.redteam_suite
```

### 4. Run the Production Gateway API
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 📁 Repository Structure

```text
conformity-gateway/
├── app/
│   ├── __init__.py
│   ├── main.py                   # Production FastAPI service with lifespan hooks
│   ├── gateway/                  # Ingress & Egress Security Boundaries
│   │   ├── sanitizers.py         # Delimiter isolation & cipher inspection
│   │   ├── canary.py             # Ephemeral sentinel generation & egress scan
│   │   └── ood_filter.py         # Latent Mahalanobis distance screener
│   ├── agent/                    # Governed LangGraph State Machine
│   │   ├── state.py              # Unified AgentState & Pydantic schemas
│   │   ├── nodes.py              # Retrieval, grading, rewriting, & generation
│   │   ├── graph.py              # Cyclical StateGraph compilation
│   │   └── tools.py              # Zero-Trust parameter-bound banking tools
│   ├── telemetry/                # Compliance & Telemetry Engine
│   │   ├── drift_monitor.py      # KS-test & Wasserstein drift monitoring
│   │   └── audit_logger.py       # EU AI Act Art. 12 SHA-256 JSONL logger
│   └── database/
│       └── vector_store.py       # Pre-retrieval tenant-isolated ChromaDB
├── benchmarks/
│   └── redteam_suite.py          # Automated adversarial benchmark runner
├── tests/
│   ├── test_stage1.py            # Vector isolation & Pydantic schema tests
│   ├── test_gateway.py           # Sanitizer, canary, and OOD screener tests
│   ├── test_agent_graph.py       # LangGraph cyclical execution & HITL tests
│   └── test_telemetry.py         # Drift statistics & audit digest tests
├── deploy/
│   ├── Dockerfile                # Multi-stage non-root container (UID 10001)
│   └── docker-compose.yml        # Orchestration configuration
├── requirements.txt
├── .gitignore
└── README.md
```