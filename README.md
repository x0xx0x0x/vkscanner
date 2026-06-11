# VK Scanner — Voight-Kampff Phishing Detector

<p align="center">
  <strong>🛡️ Automated Phishing & Forensics Detection Tool</strong><br>
  A comprehensive suite designed for deep forensic analysis of URLs, emails, and documents. VK Scanner helps security professionals detect phishing attempts, obfuscated payloads, and social engineering attacks.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/react-18-61dafb?logo=react" alt="React">
  <img src="https://img.shields.io/badge/fastapi-0.115-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/docker-ready-2496ED?logo=docker" alt="Docker">
</p>

---

## 🔑 Core Pillars

1. **🔒 100% Offline & Private:** VK Scanner does not send your files or URLs to external cloud services (like VirusTotal or urlscan.io). All heuristic checks, payload parsing, and password cracking are performed strictly on your local machine, ensuring sensitive data is never leaked.
2. **🐳 Docker Sandboxing:** The entire analysis engine is fully containerized. Detonating suspicious files or executing potentially malicious JavaScript is safely isolated from your host operating system within a Docker sandbox.
3. **🌐 Dynamic URL Analysis:** Instead of relying purely on static blacklists, VK Scanner dynamically detonates URLs (using headless browsers like Playwright) to bypass evasion techniques, capture dynamic DOM changes, and detect mobile/desktop cloaking.

---

## 🚀 Quick Start (One Command)

Our automated script ensures a seamless "Install and Run" experience without any manual configurations.

```bash
git clone https://github.com/YOUR_USERNAME/vkscanner.git
cd vkscanner
chmod +x setup.sh && ./setup.sh
```

**What the setup script does:**
1. ✅ **Installs Docker** (Debian/Ubuntu/Kali/Fedora/Arch/macOS)
2. ✅ **Configures Docker permissions**
3. ✅ **Builds and starts all sandbox services** in detached mode
4. ✅ **Installs Python dependencies** required for local CLI execution
5. ✅ **Creates a global system command (`vkscanner`)**

**After setup:**
- 💻 **Global CLI**: Run `vkscanner` from anywhere!
- 🌐 **Web Portal**: [http://localhost:3000](http://localhost:3000) (or launch using `vkscanner -w`)
- 🔌 **API**: [http://localhost:8000](http://localhost:8000)

---

### 💻 Command Line Interface (CLI) Examples

Perform secure, offline scans directly from your terminal:

```bash
# 1. Launch the web suite and open your browser:
vkscanner -w

# 2. Open the interactive step-by-step menu:
vkscanner

# 3. Scan a URL displaying detailed heuristic traces:
vkscanner url "http://paypal-verification-account-update.ga/login" --trace

# 4. Parse and scan an email file (.eml or .msg):
vkscanner email "/path/to/suspicious.eml"

# 5. Scan an Office document for malicious macros:
vkscanner document "invoice.xlsm"

# 6. Scan an encrypted ZIP with brute-force dictionary attack:
vkscanner document "financials.zip" --brute-force

# 7. Scan an encrypted PDF using a known password:
vkscanner document "secret.pdf" --password "infected123"
```

---

## 🔍 Deep Capabilities

### 🌐 URL Analysis
- **Dynamic Detonation:** Renders pages to defeat obfuscation and cloaking.
- **Homograph & Typosquatting:** Levenshtein distance checks and Cyrillic/Latin lookalike detection.
- **Structural Analysis:** Suspicious TLDs, IP-based URLs, double extensions, non-standard ports.
- **Obfuscation Detection:** Decodes hidden Javascript payloads and nested DOM events.

### ✉️ Deep Email Forensics
- **File Parsing:** Natively handles `.eml` and `.msg` uploads.
- **Header Analysis:** SPF, DKIM, DMARC validation, and mail hop analysis to detect spoofing.
- **Attachment Extraction:** Automatically pulls embedded files and scans them recursively.

### 📄 Document & Payload Dissection
- **YARA Signature Scanning:** Evaluates files, payloads, and extracted artifacts against custom YARA rules to detect known malware and advanced persistent threats (APTs).
- **PDF Analysis:** JavaScript detection and Launch/SubmitForm action scraping via PyMuPDF.
- **Office Documents (DOCX/XLSX):** VBA macro detection, OLE objects, and external reference tracing.
- **Local Password Cracking:** Built-in brute-force engine for protected PDF/ZIP/Office documents using default dictionaries or custom wordlists.

### 🧠 Advanced Heuristics
- **Social Engineering Detection:** NLP sentiment analysis for urgency/threat keyword detection.
- **Rule Engine:** A highly optimized heuristic weighting system calculating a final 0-100 Risk Score.
- **Trace Logging:** Provides a step-by-step debug trace explaining exactly which rule triggered an alert and why.

---

## 🏗️ Project Structure

```
vkscanner/
├── setup.sh                 # One-command installer & run script
├── docker-compose.yml       # Sandbox container orchestration
├── backend/                 # FastAPI, SQLite, and Heuristic Engines
│   ├── app/
│   │   ├── analyzers/       # URL, Email, and Document analysis logic
│   │   └── utils/           # Offline bruteforce and scoring algorithms
├── frontend/                # React application source
└── README.md
```

---

## 📄 License

GNU AGPLv3
