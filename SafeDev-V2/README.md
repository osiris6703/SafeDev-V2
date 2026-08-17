# 🛡️ SafeDev V2 — AI-Powered Security-Guarded Package Manager

> **Pre-installation Static Analysis & Security Guard for Python (PyPI) and Node.js (npm)**

SafeDev V2 is a unified, security-guarded package manager CLI that automatically scans open-source packages for supply-chain attacks, typosquatting, obfuscated payloads, and malicious code **BEFORE** allowing installation or execution in your development environment.

---

## ⚡ Key Highlights & Features

- 🔒 **Absolute Pre-Installation Boundary**: Analyzed packages are **NEVER** installed, imported, or executed during security scans.
- 🤖 **Dual-Ecosystem Machine Learning Classifiers**:
  - **PyPI (Python)**: Trained `XGBoost` Classifier evaluating **68 static AST and security features** (Operational Threshold: `0.38`).
  - **npm (JavaScript)**: Trained `GradientBoostingClassifier` with `StandardScaler` evaluating **48 regex, entropy, and metadata features** (Operational Threshold: `0.13`).
- ⚡ **Ultra-Fast Execution (~4s)**:
  - Multithreaded static AST feature extraction across CPU cores (`ThreadPoolExecutor`).
  - Automatic IPv4 socket resolution optimization (eliminates 30-second Windows dual-stack IPv6 timeouts).
  - Priority retrieval of release wheels (`.whl`) for 10x faster download and instant in-memory zip extraction.
- 🛠️ **Unified CLI Wrapper**: Full suite of package management commands (`install`, `upgrade`, `uninstall`, `list`, `scan`) for both Python (`pip`) and npm (`Node.js`).
- 🛡️ **Fail-Closed Architecture**: Any unhandled network error, corrupt archive, or schema mismatch defaults to `ANALYSIS_ERROR` (Exit 3) — unanalyzed packages are **NEVER** marked `SAFE`.

---

## 🚀 Quick Start & Installation

### 1. Environment Setup
```powershell
# Navigate to repository
cd D:\safedev\SafeDev-V2

# Create virtual environment
python -m venv .venv

# Activate environment (PowerShell)
.\.venv\Scripts\Activate.ps1

# Upgrade pip & install SafeDev V2 in editable mode
python -m pip install --upgrade pip
pip install -e .
```

### 2. Verify Installation
```powershell
safedev --version
# Output: SafeDev 2.0.0

pytest tests/ -v
# Output: 5 passed in ~4.2s
```

---

## 💻 COMPLETE COMMAND REFERENCE

### 1. Python (PyPI / pip) Commands

| Command | Shortcut | Description |
| :--- | :--- | :--- |
| `safedev install requests -p` | `safedev -p requests` | Pre-installation scan & prompt to install PyPI package |
| `safedev install requests==2.31.0 -p` | `safedev -p requests==2.31.0` | Scan & install specific PyPI package version |
| `safedev install requests -p -y` | `safedev -p requests -y` | Auto-confirm installation if verdict is `SAFE` |
| `safedev upgrade requests -p` | `safedev update requests -p` | Pre-upgrade scan & run `pip install --upgrade requests` |
| `safedev uninstall requests -p` | `safedev remove requests -p` | Uninstall Python package (`pip uninstall -y requests`) |
| `safedev list -p` | — | List installed Python packages (`pip list`) |
| `safedev scan requests -p` | `safedev analyze requests -p` | Security scan ONLY (no install prompt) |

---

### 2. Node.js (npm / Node) Commands

| Command | Shortcut | Description |
| :--- | :--- | :--- |
| `safedev install express -n` | `safedev -n express` | Pre-installation scan & prompt to install npm package |
| `safedev install @angular/core` | `safedev -n @angular/core` | Scan & install scoped npm package (auto-detected as npm) |
| `safedev install express@4.18.2 -n` | `safedev -n express@4.18.2` | Scan & install specific npm package version |
| `safedev install express -n -y` | `safedev -n express -y` | Auto-confirm installation if verdict is `SAFE` |
| `safedev upgrade express -n` | `safedev update express -n` | Pre-upgrade scan & run `npm update express` |
| `safedev uninstall express -n` | `safedev remove express -n` | Uninstall npm package (`npm uninstall express`) |
| `safedev list -n` | — | List installed npm packages (`npm list`) |
| `safedev scan express -n` | `safedev analyze express -n` | Security scan ONLY (no install prompt) |

---

### 3. CI/CD & JSON Commands

```powershell
# Output structured JSON report for CI/CD integration
safedev scan requests -p --format json
```

**JSON Output Example**:
```json
{
  "package_name": "requests",
  "version": "2.31.0",
  "ecosystem": "pypi",
  "verdict": "SAFE",
  "confidence": 0.3225,
  "malicious_probability": 0.0575,
  "threshold": 0.38,
  "evidence": [],
  "error_message": null
}
```

---

## 🚦 Exit Codes

| Exit Code | Verdict / Status | Description |
| :---: | :--- | :--- |
| `0` | **SAFE** | Analysis passed; malicious probability < threshold. |
| `1` | **SUSPICIOUS** | Elevated threat risk detected, or `--help` shown. |
| `2` | **MALICIOUS** | Threat detected; probability >= threshold. |
| `3` | **ANALYSIS_ERROR** | **Fail-Closed Error** (network error, malformed archive, schema error). |

---

## 🧪 Testing & Verification

Run the complete automated unit test suite:
```powershell
pytest tests/ -v
```

Test Results:
- `tests/test_archive.py::test_safe_path_traversal` **PASSED**
- `tests/test_archive.py::test_zip_extraction_limits` **PASSED**
- `tests/test_models.py::test_pypi_model_contract` **PASSED**
- `tests/test_models.py::test_npm_model_contract` **PASSED**
- `tests/test_models.py::test_predictor_fail_closed_on_invalid_features` **PASSED**

---

## 📁 Repository Structure

```text
D:\safedev\SafeDev-V2/
├── pyproject.toml                     (Build & package metadata)
├── requirements.txt                   (Production runtime dependencies)
├── requirements-dev.txt               (Development & testing dependencies)
├── README.md                          (Production documentation)
├── USAGE.txt                          (Comprehensive operational manual)
├── model_artifacts/                   (Trained inference models)
│   ├── pypi/                          (XGBoost 68-feature classifier)
│   └── npm/                           (GradientBoosting 48-feature classifier)
├── src/safedev/                       (Production source code)
│   ├── cli/main.py                    (Interactive CLI entry point)
│   ├── core/                          (Models, Config, Exceptions)
│   ├── ingestion/                     (Archive reader, Package fetcher, Resolver)
│   ├── analyzers/                     (PyPI & npm static feature extractors)
│   ├── inference/                     (Model loader, Validator, Predictor)
│   └── reporting/                     (JSON and text output formatters)
└── tests/                             (Pytest unit test suite)
```
