# SOC Email Threat Analyzer

A complete, functional desktop security tool designed for SOC Tier 1 analysts to investigate suspicious emails and detect phishing attempts.

## Overview
This application parses `.eml` files locally, analyzes headers, authenticates senders, defangs URLs, inspects attachment metadata, analyzes body text for social engineering tactics, and calculates an explainable risk score.

It keeps all sensitive data locally on the machine, and does not require an active internet connection to run the core analysis. Optional threat intelligence lookups require explicit confirmation.

## Features
- **Local Analysis:** Completely offline parsing of `.eml` files.
- **Explainable Risk Scoring:** Transparent 0-100 score engine calculating risk.
- **Header & Auth Analysis:** Detects display-name spoofing, anomalies, and SPF/DKIM/DMARC results.
- **Phishing Detection:** Evaluates urgency, credential harvesting attempts, financial lures, and suspicious HTML elements.
- **Safe URLs & Attachments:** Defangs URLs, extracts domains, and calculates attachment SHA-256 hashes safely.
- **Optional Threat Intel:** Provides VT and URLhaus API hooks for confirmed external queries.
- **Reporting & History:** Exports findings to JSON, HTML, and TXT, and maintains a local SQLite history.
- **Modern Dark GUI:** A responsive and modern Tkinter interface using a `ttk` dark theme with Persian/English bilingual labels.

## Prerequisites
* Python 3.8+
* Windows 10/11 (Compatible with Linux and macOS as well)

## Installation & Setup

1. **Clone the repository or download the source.**

2. **Open Windows PowerShell or a terminal and navigate to the project folder:**
   ```powershell
   cd path\to\soc_email_analyzer
   ```

3. **Install the dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Run the Application:**
   ```powershell
   python main.py
   ```

## Usage
1. Click **Open .eml File** and select a suspected email.
2. The analysis runs asynchronously without blocking the UI.
3. Review the overview, risk score, severity, headers, findings, URLs, and attachment tabs.
4. If a suspicious attachment hash is found, right-click it in the Attachments tab to look it up on VirusTotal (Requires API key configured via **Threat Intel Settings**).
5. Click **Export HTML/JSON/TXT Report** from the Overview tab to generate an incident report.

## Tests
You can run the built-in test suite, which creates benign and malicious `.eml` files on the fly to test the scoring engine and parsers:
```powershell
python -m unittest discover -s soc_email_analyzer/tests
```

## Architecture
- `main.py`: Entry point.
- `soc_email_analyzer/gui/`: Tkinter presentation layer.
- `soc_email_analyzer/analyzer/`: Business logic for parsing, scoring, and detecting anomalies.
- `soc_email_analyzer/db/`: Local SQLite history storage.
- `soc_email_analyzer/report/`: Reporting logic for HTML, TXT, and JSON.
- `soc_email_analyzer/threat_intel/`: Integrations.
- `soc_email_analyzer/tests/`: Unit tests and sample generators.

## Disclaimer
This is an analysis tool and does not guarantee complete accuracy. Attackers frequently change tactics. An analyst should review findings manually before making final security decisions.
