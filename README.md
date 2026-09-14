# ANVESH (अन्वेष) — Cyber Forensic Intelligence Platform

<p align="center">
  <img src="web/public/brand/anvesh-logo-wide-transparent.png" alt="ANVESH Banner" width="480" />
</p>

<p align="center">
  <strong>Smart India Hackathon 2026 | Problem Statement SIH26106</strong><br>
  <em>AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black" alt="React 18" />
  <img src="https://img.shields.io/badge/React_Native-Expo_51-000020?style=flat&logo=expo&logoColor=white" alt="Expo" />
  <img src="https://img.shields.io/badge/TypeScript-5.5-3178C6?style=flat&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E?style=flat&logo=supabase&logoColor=white" alt="Supabase" />
  <img src="https://img.shields.io/badge/Status-Production_Ready-30D158?style=flat" alt="Production Ready" />
  <img src="https://img.shields.io/badge/Compliance-SIH26106-FF9F0A?style=flat" alt="SIH26106" />
</p>

---

## 📑 Table of Contents
- [Executive Overview](#-executive-overview)
- [System Architecture](#-system-architecture)
- [Multi-Tier AI & Machine Learning Architecture](#-multi-tier-ai--machine-learning-architecture)
- [Key Forensic Capabilities](#-key-forensic-capabilities)
- [Forensic Attribution Safeguard (Ethical Invariant)](#-forensic-attribution-safeguard-ethical-invariant)
- [Project Directory Structure](#-project-directory-structure)
- [Technology Stack](#-technology-stack)
- [Quick Start Guide](#-quick-start-guide)
- [API Reference](#-api-reference)
- [Pre-Packaged Forensic Test Scenarios](#-pre-packaged-forensic-test-scenarios)
- [Security & Chain of Custody](#-security--chain-of-custody)
- [License & Contributors](#-license--contributors)

---

## 🎯 Executive Overview

**ANVESH (अन्वेष)** is a forensic-grade cyber intelligence platform engineered to ingest, deconstruct, analyze, and attribute suspicious emails. Built specifically for law enforcement, Security Operations Centers (SOCs), and incident response analysts, ANVESH bridges the gap between raw RFC-822 message headers and actionable legal intelligence.

### The Problem (SIH26106)
Modern email threats exploit trust through sophisticated impersonation techniques:
- **Business Email Compromise (BEC)** using display-name spoofing and urgent financial coercion.
- **Lookalike Domains (Typosquatting / Homoglyphs)** that mimic legitimate banking and enterprise portals.
- **Multi-Hop Relay Masking** routing through Tor exit nodes and bulletproof residential proxies.
- **Premature / False Attribution** falsely accusing innocent victims whose servers or spoofed names were abused.

### The ANVESH Solution
ANVESH provides a **Zero-Fabrication** evidence analysis pipeline combining cryptographic authentication verification, authoritative BGP telemetry, multi-model machine learning, and explainable signal fusion with an immutable chain of custody.

---

## 🏗️ System Architecture

```
                                  ANVESH PLATFORM
                                         │
         ┌───────────────────────────────┴───────────────────────────────┐
         ▼                                                               ▼
   Web SOC Workstation                                          Mobile Companion App
(React 18 + Vite + Tailwind)                                    (React Native + Expo)
   Density Tier: 8 / 10                                         Real-time Alert Triage
Deep Investigation & Campaign Graph                             On-call Incident Review
         │                                                               │
         └───────────────────────────────┬───────────────────────────────┘
                                         │ RESTful HTTPS / JSON
                                         ▼
                             FastAPI Core Engine Monolith
                         (Python 3.12 · Pydantic v2 · Async)
                                         │
      ┌───────────────────┬──────────────┴───────┬───────────────────┐
      ▼                   ▼                      ▼                   ▼
RFC-822 Parser      BGP & Tor Intel        ML Pipeline          Signal Fusion
• SHA-256 Hashing   • ASN Resolution       • Model 1 (Phish)    • Explainable Score
• Header Extraction • Tor Exit Node Check  • Model 2 (BEC)      • Category Breakdown
• Relay Traversal   • RDAP / GeoIP         • Model 3A/3B (Spoof)• Gap Analysis
      │                   │                      │                   │
      └───────────────────┼──────────────────────┴───────────────────┘
                          ▼
             PostgreSQL Relational Ledger
                 (Supabase Cloud DB)
          • Cases & Evidence Table
          • Append-Only Audit Trail
          • Campaign Correlation Graph
```

---

## 🧠 Multi-Tier AI & Machine Learning Architecture

ANVESH does not rely on a single black-box model. It implements a **4-Tier Specialized AI/ML Pipeline** paired with an **Explainable Signal Fusion Engine**:

```
Raw Message Payload (Headers + Body)
 │
 ├──► [Model 1] Phishing NLP Vector Classifier (TF-IDF + Calibrated Logistic Regression)
 │    └── Detects credential harvesting patterns, psychological urgency, and phishing vectors.
 │
 ├──► [Model 2] Business Email Compromise (BEC) Detector
 │    └── Scans for financial coercion, wire transfer demands, executive pressure, and swift tampering.
 │
 ├──► [Model 3A] Identity Impersonation Engine (Heuristic & Discrepancy Matching)
 │    └── Evaluates display-name vs mailbox local-part mismatches and reply-to discrepancies.
 │
 ├──► [Model 3B] Lookalike Domain Detector (Frozen Levenshtein / Jaro-Winkler Metric Matrix)
 │    └── Detects leet-speak character substitutions (e.g. `paypa1.com` vs `paypal.com`), homoglyphs, and subdomains.
 │
 └──► [Phase 9B] Forensic Signal Fusion Engine
      └── Aggregates all model signals + cryptographic authentication (SPF/DKIM/DMARC) + BGP telemetry
          into an explainable normalized threat score (0 - 100).
```

### Model Summary Table

| Model Identifier | Purpose | Primary Features | Verdict Category |
| :--- | :--- | :--- | :--- |
| **Model 1 (NLP-Vector-v2.1)** | Phishing Classification | TF-IDF, N-grams, harvesting lexicons, call-to-action density | `PHISHING` / `BENIGN` |
| **Model 2 (BEC-v1.0)** | BEC & Wire Fraud Detection | Urgency keywords, financial coercion phrases, payment context | `BEC_FINANCIAL_PRESSURE` |
| **Model 3A (Identity-v1)** | Display Name Impersonation | Local-part distance, sender vs claim divergence, reply-to offset | `IDENTITY_DISCREPANCY` |
| **Model 3B (Lookalike-v1)** | Typosquatting / Homoglyph | Levenshtein distance, Jaro-Winkler, TLD match, digit replacement | `LOOKALIKE_DOMAIN` |
| **Forensic Signal Fusion** | Synthesis & Normalization | Cross-corroboration of ML + Auth + BGP + Threat Intel | **0 - 100 Normalized Score** |

---

## ⚡ Key Forensic Capabilities

### 1. RFC-822 Parsing & Cryptographic Evidence Ledger
- Instant SHA-256 evidence fingerprinting on ingestion.
- Full MIME body and header reconstruction (`From`, `To`, `Subject`, `Message-ID`, `Return-Path`, `Reply-To`).
- Complete `Received:` header hop traversal from perimeter recipient back to the probable origin IP.

### 2. Cryptographic Authentication Matrix
- Evaluates **SPF (Sender Policy Framework)**, **DKIM (DomainKeys Identified Mail)**, and **DMARC (Domain-based Message Authentication)**.
- Distinguishes between administrative policy failures and active cryptographic tampering.

### 3. Authoritative BGP Telemetry & Tor Detection
- Autonomous System Number (ASN) and BGP route lookup.
- Deterministic RFC 1918 private vs public routable IP classification.
- Real-time Tor exit node and anonymizing proxy detection.

### 4. Lookalike Domain & Typosquatting Analysis
- On-demand lexical analysis comparing candidate sender domains against a curated corpus of high-value brands.
- Flags homoglyph character substitutions (e.g. `1` for `l`, `0` for `o`, `rn` for `m`).

### 5. Campaign Correlation Engine
- Groups disparate cases into coordinated campaigns using temporal proximity, shared Reply-To addresses, identical BGP subnets, and subject line similarities.

### 6. Analyst Workflow & Adjudication Lifecycle
- Append-only notes ledger (forensic observations cannot be deleted or overwritten).
- Formal analyst lifecycle state transitions: `NEW` ➔ `TRIAGED` ➔ `INVESTIGATING` ➔ `ESCALATED` ➔ `RESOLVED` ➔ `CLOSED`.
- Mandatory justification required for all escalation and adjudication actions.

### 7. Court-Admissible Dossier Export
- One-click export of formal forensic investigation dossiers in **PDF** format (using ReportLab) and raw **JSON** evidence formats.

---

## ⚖️ Forensic Attribution Safeguard (Ethical Invariant)

A core tenet of the ANVESH platform is **evidentiary neutrality**:

> **Attribution Boundary:**  
> *Technical email headers, SMTP hops, and IP lookups identify transit infrastructure and network gateways ONLY. Individual physical human identity CANNOT be established solely from transport headers.*

ANVESH enforces this invariant across all screens and reports:
- All assessment cards explicitly state: `Actor Identity: NOT ESTABLISHED`.
- Guarantees that server administrators, compromised tenant owners, or VPN providers are never falsely attributed as the physical attacker without formal subpoena and ISP log correlation.

---

## 📂 Project Directory Structure

```
SIH2026/
├── backend/                        # FastAPI Core Backend Monolith
│   ├── app/
│   │   ├── api/v1/endpoints/       # REST API endpoints (cases, emails, intel, etc.)
│   │   ├── core/                   # Security, configs, constants, forensic terms
│   │   ├── database/               # Supabase PostgREST client & schemas
│   │   └── services/               # Parsers, BGP intel, ML inference, reports
│   ├── tests/                      # Pytest suite & forensic fixture emails
│   └── run.py                      # Local server entry point
│
├── web/                            # Primary SOC Analyst Web Workstation
│   ├── src/
│   │   ├── components/             # Risk badges, command palette, error boundaries
│   │   │   ├── common/             # Reusable UI components & ErrorBoundary
│   │   │   ├── investigation/      # Analyst workflow, report modal, observables
│   │   │   └── layout/             # Top navigation command bar
│   │   ├── pages/                  # Dashboard, Workspace, Cases, Alerts, Intel, Campaigns
│   │   └── App.tsx                 # Main application shell
│   ├── package.json
│   └── vite.config.ts
│
├── mobile/                         # Mobile Companion Application (Android / iOS)
│   ├── src/
│   │   ├── components/             # Native cards, risk indicators, connectivity pill
│   │   ├── screens/                # Home, Cases, Alerts, Detail, Quick Lookup
│   │   ├── navigation/             # Native stack & bottom tab navigators
│   │   └── constants/              # Centralized API base URL & theme tokens
│   ├── app.json                    # Expo project configuration
│   ├── eas.json                    # EAS cloud build profiles
│   └── App.tsx                     # Mobile entry point with ErrorBoundary
│
├── ml/                             # Machine Learning Subsystem
│   ├── datasets/                   # Curated, source-aware training & evaluation sets
│   ├── inference/                  # Frozen model predictors (Phishing, BEC, Lookalike)
│   ├── models/                     # Serialized scikit-learn models & feature hashes
│   └── evaluation/                 # Metrics, benchmark scripts & validation logs
│
├── supabase/                       # Supabase PostgreSQL Migrations
│   └── migrations/                 # Schema tables, indices, RLS policies
│
└── docs/                           # Documentation, operator manuals & checklists
```

---

## 💻 Technology Stack

| Layer | Technologies Used | Key Rationale |
| :--- | :--- | :--- |
| **Backend** | Python 3.12, FastAPI, Pydantic v2, Uvicorn | High-performance asynchronous API, strict schema validation |
| **Machine Learning** | Scikit-learn, NumPy, Joblib | Deterministic inference speed (< 15ms), frozen reproducible models |
| **Web Workstation** | React 18, Vite, TypeScript, Tailwind CSS, Lucide | Swiss minimalist dark SOC theme, zero bloat, instant HMR |
| **Mobile App** | React Native, Expo 51, React Navigation, Hermes | Standalone Android APK support, fast on-call alert triage |
| **Database & Auth** | Supabase (PostgreSQL 15), Row-Level Security | Real-time event synchronization, relational integrity |
| **Reporting Engine** | ReportLab PDF Library | High-resolution, tamper-evident forensic export documents |

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.12+**
- **Node.js 20+** & `npm`
- **Git**

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/Rishabhbansal005/Anvesha.git
cd Anvesha
```

---

### Step 2: Configure Environment Variables
Copy the sample environment file and configure your credentials:
```bash
cp .env.example .env
```

Key environment variables:
```ini
SUPABASE_URL=https://your-supabase-id.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-key
JWT_SECRET=your-secure-jwt-secret
ENVIRONMENT=development
```

---

### Step 3: Run the Backend
```bash
cd backend
python -m venv venv

# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
* **API Documentation (Swagger UI)**: `http://localhost:8000/docs`
* **Health Check**: `http://localhost:8000/api/v1/health`

---

### Step 4: Run the Web SOC Workstation
In a new terminal:
```bash
cd web
npm install
npm run dev
```
* Open **`http://localhost:5173`** in your browser.

---

### Step 5: Run the Mobile Companion App
In a new terminal:
```bash
cd mobile
npm install
npx expo start
```
* Scan the QR code with **Expo Go** on Android/iOS, or install the compiled standalone APK.

---

## 📡 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service health, version, and Supabase connectivity status |
| `POST` | `/api/v1/emails/analyze` | Ingest `.eml` file or raw headers; executes full forensic pipeline |
| `GET` | `/api/v1/cases` | Paginated investigation ledger with risk and status filters |
| `GET` | `/api/v1/cases/{case_id}` | Complete forensic dossier (email, hops, ML, intel, fusion) |
| `PATCH` | `/api/v1/cases/{case_id}/status` | Transition investigation status with mandatory justification |
| `POST` | `/api/v1/cases/{case_id}/decision` | Record analyst adjudication verdict |
| `GET` | `/api/v1/cases/{case_id}/notes` | Retrieve append-only forensic investigation notes ledger |
| `POST` | `/api/v1/cases/{case_id}/notes` | Append a new forensic note |
| `GET` | `/api/v1/cases/{case_id}/activity` | Unified chronological timeline of system findings and analyst actions |
| `GET` | `/api/v1/cases/{case_id}/report/pdf` | Export court-admissible PDF dossier |
| `GET` | `/api/v1/cases/{case_id}/report/json` | Export raw JSON evidence dossier |
| `GET` | `/api/v1/intelligence/ip/{ip}` | On-demand BGP, ASN, Geolocation, and Tor indicator lookup |
| `GET` | `/api/v1/intelligence/domain/{domain}` | On-demand lexical lookalike, RDAP, and DNS analysis |
| `GET` | `/api/v1/campaigns` | Retrieve all active correlated threat campaigns |

---

## 🧪 Pre-Packaged Forensic Test Scenarios

The repository includes realistic RFC-822 fixtures for immediate end-to-end testing located in `backend/tests/fixtures/sih_demo/`:

| Scenario File | Threat Type | Key Indicators | Expected Score |
| :--- | :--- | :--- | :--- |
| **`scenario_01_classic_phishing.eml`** | Credential Harvesting | Tor Exit Relay, Lookalike `paypa1-secure.com`, SPF/DKIM Fail | `CRITICAL (99/100)` |
| **`scenario_02_bec_payment_change.eml`** | BEC Financial Coercion | Urgency ("wire transfer"), Reply-To mismatch, Campaign match | `HIGH (80/100)` |
| **`scenario_03_lookalike_spoofing.eml`** | Brand Impersonation | Homoglyph typosquatting (`rnicrosoft.com`), Levenshtein diff | `HIGH (85/100)` |
| **`scenario_06_benign_corporate.eml`** | Clean Corporate Message | Valid SPF, DKIM pass, DMARC alignment, clean IP reputation | `LOW (0/100)` |

You can ingest any test scenario directly via `curl`:
```bash
curl -X POST -F "file=@backend/tests/fixtures/sih_demo/scenario_01_classic_phishing.eml" http://localhost:8000/api/v1/emails/analyze
```

---

## 🔒 Security & Chain of Custody

1. **SHA-256 Evidence Hashing**: Every ingested email message is fingerprinted immediately. The hash is immutably stored in the evidence ledger.
2. **Append-Only Auditing**: Analyst notes and activity records can never be edited or deleted once committed.
3. **Preservation Invariant**: Cases with active forensic evidence are protected from deletion to ensure chain of custody for legal proceedings.
4. **Environment Isolation**: No API keys or sensitive credentials are committed to version control; all secrets are managed via strictly ignored `.env` profiles.

---

## 📜 License & Contributors

Built with precision for **Smart India Hackathon 2026** by team **Anvesha**.

- **License**: [MIT License](LICENSE)
- **Problem Statement**: SIH26106 — *AI-Powered Email Threat Detection and Forensic Intelligence*
- **Primary Repository**: [https://github.com/Rishabhbansal005/Anvesha](https://github.com/Rishabhbansal005/Anvesha)
