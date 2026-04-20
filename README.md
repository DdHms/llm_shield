# LLM Shield 🛡️

A privacy-preserving proxy for Large Language Models (LLMs) that automatically identifies and redacts Personal Identifiable Information (PII) from prompts before they reach the provider, then restores the original data in the model's response.

---

## ✨ Features

- **🛡️ PII Detection & Redaction**: Uses Microsoft Presidio, Spacy, and custom regex to identify:
    - Standard PII (Names, Emails, Locations, Phone Numbers, etc.)
    - IPv4 Addresses
    - Environment Variables (e.g., `MY_KEY = secret_value`)
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

## 📊 Monitoring

The built-in dashboard provides real-time visibility into the scrubbing and de-scrubbing process. You can view original requests, their redacted versions, and how the responses were restored.

> **Note:** To keep the display clean and focused on content, the dashboard automatically filters out internal metadata such as Gemini's `thoughtSignature` from the prettified JSON view.

![Dashboard Example](images/dashboard.png)
![Dashboard Example](images/settings.png)


---

## ⚙️ Configuration

LLM Shield is configured using Environment Variables.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ANALYZER_TYPE` | `pattern` | `pattern` (Fast Regex), `presidio` (Deep NLP), or `both`. |
| `SCRUBBING_MODE` | `generic` | `generic` (redact all as `<PRIVATE_DATA>`) or `semantic` (redact by label). |
| `DEFAULT_EXCLUSIONS` | `""` | Comma-separated list of strings to ALWAYS redact (e.g., internal server names). |
| `TARGET_URL` | `https://cloudcode-pa.googleapis.com` | The destination LLM API. |
| `DEBUG` | `false` | Set to `true` for verbose processing logs. |
| `HEADLESS` | `false` | Set to `true` to skip launching the GUI window (useful for Docker/Servers). |

---

## 🚀 Installation

Choose the method that best fits your workflow.

### 1. Standalone Native App (Easiest)
Download a single executable that includes everything you need. No Python, Node, or Rust installation required.

1.  **Download**: Go to the [Releases](https://github.com/Ddyedidya/llm-shield/releases) page and download the binary for your OS:
    *   `LLMShield-windows.exe` (Windows)
    *   `LLMShield-macos-silicon` (Apple Silicon M1/M2/M3)
    *   `LLMShield-macos-intel` (Intel Mac)
    *   `LLMShield-linux` (Linux)
2.  **Permissions (Mac/Linux only)**: Open your terminal and grant execution permission:
    ```bash
    chmod +x LLMShield-macos-silicon
    ```
3.  **Run**: Double-click the file (Windows) or run from terminal:
    ```bash
    ./LLMShield-macos-silicon
    ```

### 2. Docker (Recommended for Servers)
The most portable way to run the shield, especially in headless or cloud environments.

```bash
docker run -d -p 8080:8080 --name llm-shield llm-proxy-pii
```

### 3. NPM (Local/Development)
Best if you want to integrate the shield into a Node.js project or modify the source code.

```bash
npm install
npm run build
npm start
```

---

## ⚙️ Usage & Configuration

Regardless of how you installed the shield, you can configure its behavior using Environment Variables.

### Common Configuration Options
| Variable | Default | Description |
| :--- | :--- | :--- |
| `DEFAULT_EXCLUSIONS` | `""` | Comma-separated list of strings to ALWAYS redact. |
| `ANALYZER_TYPE` | `pattern` | `pattern` (Fast Regex), `presidio` (Deep NLP), or `both`. |
| `SCRUBBING_MODE` | `generic` | `generic` (redact as `<PRIVATE_DATA>`) or `semantic` (redact by label). |
| `HEADLESS` | `false` | Set to `true` to skip launching the GUI window. |

### Running with Variables

**Mac / Linux (Zsh or Bash)**
```bash
DEFAULT_EXCLUSIONS="my-project-name,internal-ip" ANALYZER_TYPE=both ./LLMShield-macos-silicon
```

**Windows (PowerShell)**
```powershell
$env:DEFAULT_EXCLUSIONS="my-project-name"; $env:ANALYZER_TYPE="both"; .\LLMShield-windows.exe
```

**Docker**
```bash
docker run -d -p 8080:8080 -e DEFAULT_EXCLUSIONS="secret-val" llm-proxy-pii
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

