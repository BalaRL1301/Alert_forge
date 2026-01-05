# AlertForge: Next-Gen Hybrid SIEM & Threat Detection System

AlertForge is an advanced Security Information and Event Management (SIEM) prototype designed to demonstrate the future of autonomous cyber defense. It combines traditional signature-based detection with modern anomalies (Machine Learning) and GenAI-powered incident analysis.

## 🚀 Project Overview & Achievements

This system successfully integrates the following advanced modules:

1.  **Live Operations Center (`/live`)**:
    *   Real-time telemetry streams visualizing network ingress traffic.
    *   Live scrolling terminal log matching "hacker" aesthetics for immediate visual feedback.
    *   Attack origin mapping and threat category visualization.

2.  **Logs Explorer (`/logs`)**:
    *   Deep-dive forensic tool for inspecting historical events.
    *   Full-text search, threat-status filtering, and JSON payload inspection.
    *   **GenAI Integration**: Automated "Analyst Reports" explaining *why* a specific packet was flagged.

3.  **Threat Intelligence (`/threats`)**:
    *   Dashboard for global threat vectors and active campaigns.
    *   **Rule Library**: Dynamic viewer for active YARA detection rules (SQLi, XSS, etc.).

4.  **Red Team Simulator (`/simulator`)**:
    *   Built-in attack capability to self-audit the system.
    *   Launch real SQL Injection, XSS, and Brute Force attacks against the internal Vulnerable App to validate defenses in real-time.

5.  **GenAI Incident Response**:
    *   An embedded AI engine that parses raw logs and generates natural language summaries, creating a "Human-in-the-loop" experience without human fatigue.

---

## 📄 IEEE Research Paper Context

If you are drafting a research paper (e.g., IEEE format) based on this project, you can focus on the **"Hybrid-AI Architecture for Resilient Threat Detection"**.

### 1. Abstract / Core Concept
The paper proposes a novel security architecture that bridges the gap between deterministic logic (signatures) and probabilistic reasoning (AI). Unlike traditional IDPS which relies solely on known patterns, AlertForge utilizes a multi-layered engine:
*   **Layer 1**: Deterministic Engine (YARA) for zero-latency blocking of known CVEs.
*   **Layer 2**: Stochastic Engine (Isolation Forest) for detecting zero-day anomalies.
*   **Layer 3**: Generative Engine (LLM-based) for semantic analysis and reporting.

### 2. System Architecture & Technologies

#### **Backend (The Nervous System)**
*   **Framework**: **FastAPI** (Python 3.10+) - Chosen for high-throughput asynchronous request handling (ASGI).
*   **Detection Engine**:
    *   **YARA**: Industry-standard pattern matching for signature-based detection.
    *   **Scikit-Learn**: Implements `IsolationForest` for unsupervised anomaly detection on numeric vectors (request size, frequency).
    *   **Regex & Heuristics**: Lightweight pre-filters for immediate noise reduction.
*   **GenAI Service**: A template-based NLP module (upgradable to LLM APIs) that provides semantic interpretation of attacks, reducing the "Mean Time To Understand" (MTTU) for analysts.
*   **Simulation Core**: A threaded request generator (`requests` library) acting as an internal adversary (Red Team).

#### **Frontend (The Visual Cortex)**
*   **Framework**: **Next.js 15 (React 19)** - Utilizing Server Components for performance and Client Components for interactivity.
*   **Visualization**:
    *   **Recharts**: For time-series traffic telemetry.
    *   **Framer Motion**: For smooth, hardware-accelerated UI transitions (60fps updates).
    *   **TailwindCSS**: Utility-first styling for a rapid, responsive "Cyberpunk/Enterprise" aesthetic.
*   **State Management**: Real-time polling hooks ensuring data consistency between the backend engine and the analyst dashboard.

### 3. Key Research Contributions
*   **Wait-Free Forensics**: The system demonstrates how decoupling log ingestion (Background Tasks) from analysis (API) allows for high-availability monitoring.
*   **Self-Auditing Loop**: The integration of an "Attack Simulator" directly into the defense console enables Continuous Security Validation (CSV).
*   **Semantic Alerting**: Shift from "Code 403" to "AI: SQL Injection detected targeting the Users table", demonstrating improved cognitive load for operators.
