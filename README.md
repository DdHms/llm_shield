# LLM Shield 🛡️

A privacy-preserving proxy for Large Language Models (LLMs) that automatically identifies and redacts Personal Identifiable Information (PII) from prompts before they reach the provider, then restores the original data in the model's response.

---

## ✨ Features

- **🛡️ PII Detection & Redaction**: Uses Microsoft Presidio, Spacy, and custom regex to identify:
    - Standard PII (Names, Emails, Locations, Phone Numbers, etc.)
    - IPv4 Addresses
    - Alphanumeric "Gibberish" (6+ characters, mix of letters and numbers)
- **🌓 Two Scrubbing Modes**:
    - `generic` (Default): Replaces PII with `<PRIVATE_DATA_N>`.
    - `semantic`: Replaces PII with descriptive labels like `<PERSON_N>` or `<IP_ADDRESS_N>`.
- **🛠️ Toggleable Analyzers**: Choose between `presidio` (Deep NLP), `pattern` (Fast Regex), or `both`.
- **🚫 Custom Exclusions**: Define a specific list of strings to always redact.
- **🔄 Response De-anonymization**: Automatically restores original PII in the model's response.
- **⚡ Streaming Support**: Buffering mechanism for chunked SSE responses.
- **📊 Visual Dashboard**: Real-time monitoring at `/dashboard`.
- **🚀 Gemini CLI Ready**: Designed for seamless integration with Google's Gemini CLI.

---

## ⚙️ Configuration

LLM Shield is configured using Environment Variables. You can pass these directly when starting the application.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SCRUBBING_MODE` | `generic` | `generic` or `semantic` labels. |
| `ANALYZER_TYPE` | `both` | `presidio`, `pattern`, or `both`. |
| `DEFAULT_EXCLUSIONS` | `""` | Comma-separated list of strings to always redact. |
| `TARGET_URL` | `https://cloudcode-pa.googleapis.com` | The destination LLM API. |
| `DEBUG` | `false` | Set to `true` for verbose logs. |

### How to Pass Arguments with NPM

To configure the shield, pass the environment variables **before** the `npm start` command.

#### **Mac / Linux (Zsh or Bash)**
```bash
# Example: Use semantic labels and exclude specific internal terms
SCRUBBING_MODE=semantic DEFAULT_EXCLUSIONS="my-api-key,internal-db-01" npm start
```

#### **Windows (PowerShell)**
```powershell
# Example: Use semantic labels and exclude specific internal terms
$env:SCRUBBING_MODE="semantic"; $env:DEFAULT_EXCLUSIONS="my-api-key,internal-ip"; npm start
```

---

## 🚀 Installation & Setup (The "One-Click" Way)

This method is recommended for most users. It uses pre-compiled native binaries so you **don't** need Rust or a C++ compiler installed.

### 1. Download Binaries
Download the pre-compiled `.node` files from the **GitHub Actions** tab for your OS and place them in the project root.
*   `llm-shield.x86_64-pc-windows-msvc.node` (Windows)
*   `llm-shield.x86_64-apple-darwin.node` (Mac Intel)
*   `llm-shield.aarch64-apple-darwin.node` (Mac Silicon)

### 2. Install & Run
Run these commands in your terminal:

```bash
# 1. This automatically sets up your Python environment and NLP models
npm install

# 2. This detects your OS and launches the proxy + GUI
npm start
```

---

## 🔗 Gemini CLI Integration

To route your Gemini CLI traffic through the shield, set your endpoint in your shell:

```bash
# Mac/Linux
export CODE_ASSIST_ENDPOINT="http://localhost:8080"

# Windows PowerShell
$env:CODE_ASSIST_ENDPOINT="http://localhost:8080"
```

---

## 🧪 Development & Testing

If you want to modify the Rust or Python code:

### Build from Source
**Prerequisites:** Node.js (v22+), Rust & Cargo, Python 3.10+.
```bash
npm install
npm run build
npm start
```

### Run Tests
```bash
pytest
pytest tests/test_performance.py -s
```
