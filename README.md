# LLM Privacy Proxy

A privacy-preserving proxy for LLMs (Local and Remote) that automatically identifies and redacts Personal Identifiable Information (PII) from prompts before they reach the provider, and restores the original data in the model's response.

## Features

- **PII Detection & Redaction**: Uses Microsoft Presidio, Spacy, and custom regex to identify:
    - Standard PII (names, emails, locations, phone numbers, etc.)
    - IPv4 Addresses
    - Alphanumeric "Gibberish" (6+ characters, mix of letters and numbers)
- **Two Scrubbing Modes**:
    - `generic` (Default): All PII is replaced with a standard `<PRIVATE_DATA_N>` placeholder.
    - `semantic`: PII is replaced with descriptive placeholders (e.g., `<PERSON_N>`, `<IP_ADDRESS_N>`).
- **Toggleable Analyzers**: Choose between `presidio` (Deep PII), `pattern` (Fast Regex), or `both` at build time.
- **Custom Exclusions**: Explicitly redact specific strings by passing them at build time.
- **Response De-anonymization**: Automatically restores original PII in the model's response before returning it to the client.
- **Streaming Support**: Handles chunked/streaming responses (SSE) with a buffering mechanism to prevent de-scrubbing failures on split placeholders.
- **Visual Dashboard**: Integrated web interface at `/dashboard` to monitor scrubbing and de-scrubbing in real-time.
- **Gemini CLI Integration**: Fully compatible with Gemini CLI by redirecting traffic through the proxy.

## How It Works

1.  **Intercept**: The proxy captures incoming POST requests.
2.  **Analyze & Scrub**: It parses the request body, identifies PII using the selected `ANALYZER_TYPE`, and replaces it with unique placeholders based on the `SCRUBBING_MODE`.
3.  **Map**: A temporary mapping of `placeholder -> original_value` is stored for the duration of the request.
4.  **Forward**: The scrubbed request is forwarded to the `TARGET_URL`.
5.  **Restore & Log**: When the response arrives, the proxy restores the original data and logs the transformation.
6.  **Display**: View real-time logs at `http://localhost:8080/dashboard`.

## Configuration

### Environment Variables / Build Args

| Variable | Default | Description |
|---------------------|---------|-------------|
| `SCRUBBING_MODE`    | `generic` | `generic` or `semantic` labels. |
| `ANALYZER_TYPE`     | `both`    | `presidio`, `pattern`, or `both`. |
| `DEFAULT_EXCLUSIONS`| `""`      | Comma-separated list of strings to always redact. |
| `TARGET_URL`        | `https://cloudcode-pa.googleapis.com` | The destination LLM API. |
| `DEBUG`             | `false`   | Set to `true` for verbose step-by-step logs. |

### CLI Integration

To use this proxy with the Gemini CLI, set the following environment variable in your shell:

```bash
export CODE_ASSIST_ENDPOINT="http://localhost:8080"
```

## Setup & Run

### Prerequisites

- Docker installed on your system.

### Building and Running

1.  **Build with default settings**:
    ```bash
    docker build -t llm-proxy-pii .
    ```

2.  **Run the container**:
    ```bash
    docker run -p 8080:8080 llm-proxy-pii
    ```

3.  **Run with Debugging and Custom Target**:
    ```bash
    docker run -p 8080:8080 \
      -e DEBUG=true \
      -e TARGET_URL="https://generativelanguage.googleapis.com" \
      llm-proxy-pii
    ```

The proxy will be available at `http://localhost:8080`.
The dashboard will be available at `http://localhost:8080/dashboard`.

## Development & Testing

### Set up the virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### Run Tests:
```bash
pytest
```

### Run Performance Comparison:
```bash
pytest tests/test_performance.py -s
```
