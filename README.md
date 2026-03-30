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

The application is configured using Environment Variables. These can be passed via Docker, set in your shell, or passed directly to the Node process.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SCRUBBING_MODE` | `generic` | `generic` or `semantic` labels. |
| `ANALYZER_TYPE` | `both` | `presidio`, `pattern`, or `both`. |
| `DEFAULT_EXCLUSIONS` | `""` | Comma-separated list of strings to always redact. |
| `TARGET_URL` | `https://cloudcode-pa.googleapis.com` | The destination LLM API. |
| `DEBUG` | `false` | Set to `true` for verbose logs. |

### How to Pass Arguments

#### **Mac / Linux (Zsh or Bash)**
```bash
ANALYZER_TYPE=presidio DEFAULT_EXCLUSIONS="my-api-key,internal-ip" node index.js
```

#### **Windows (PowerShell)**
```powershell
$env:ANALYZER_TYPE="presidio"; $env:DEFAULT_EXCLUSIONS="my-api-key,internal-ip"; node index.js
```

---

## 🚀 Setup & Installation

### Option 1: Using Pre-built Artifacts (Easiest)
Download pre-compiled binaries from the **GitHub Actions** tab for your OS (Windows, Mac Intel, or Mac Silicon).

1.  **Download** the artifact matching your OS.
2.  **Unzip** and place the `.node` file in the project root.
3.  **Rename** the file to `llm-shield.node`.
4.  **Run**:
    ```bash
    npm install --production  # Install Python dependencies
    node index.js
    ```

### Option 2: Docker (Containerized)
Recommended for quick setup and isolated environments.

1.  **Build**:
    ```bash
    docker build -t llm-shield .
    ```
2.  **Run**:
    ```bash
    docker run -p 8080:8080 -e SCRUBBING_MODE=semantic llm-shield
    ```

### Option 3: Build from Source (Native Node.js Addon)
Best for developers wanting the full native desktop experience.

**Prerequisites:** Node.js (v22+), Rust & Cargo, Python 3.10+.

1.  **Install & Build**:
    ```bash
    npm install
    npm run build
    ```
2.  **Start**:
    ```bash
    npm start
    ```

---

## 🔗 Gemini CLI Integration

To route your Gemini CLI traffic through the shield:

```bash
export CODE_ASSIST_ENDPOINT="http://localhost:8080"
```

---

## 🧪 Development & Testing

### Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### Run Tests
```bash
pytest
pytest tests/test_performance.py -s
```
