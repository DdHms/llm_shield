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
- **Custom Exclusions**: Explicitly redact specific strings (e.g., internal service names, cluster IDs) by passing them at build time.
- **Response De-anonymization**: Automatically restores original PII in the model's response before returning it to the client.
- **Configurable Backend**: Works with Gemini Internal APIs by default but can be configured for any endpoint.

## How It Works

1.  **Intercept**: The proxy captures incoming POST requests.
2.  **Analyze & Scrub**: It parses the request body, identifies PII using the `presidio-analyzer` and custom regex, and replaces it with unique placeholders based on the selected `SCRUBBING_MODE`.
3.  **Map**: A temporary mapping of `placeholder -> original_value` is stored for the duration of the request.
4.  **Forward**: The scrubbed request is forwarded to the `TARGET_URL`.
5.  **Restore**: When the response arrives, the proxy recursively scans the JSON for placeholders and replaces them with the original values from the mapping.

## Configuration

| Build Arg / Env Var | Default | Description |
|---------------------|---------|-------------|
| `SCRUBBING_MODE`    | `generic` | `generic` or `semantic` labels. |
| `DEFAULT_EXCLUSIONS`| `""`      | Comma-separated list of strings to always redact. |
| `TARGET_URL`        | `https://cloudcode-pa.googleapis.com` | The destination LLM API. |

## Setup & Run

### Prerequisites

- Docker installed on your system.

### Building and Running

1.  **Build with default settings (Generic Mode)**:
    ```bash
    docker build -t llm-proxy-pii .
    ```

2.  **Build with Semantic Mode and Custom Exclusions**:
    ```bash
    docker build \
      --build-arg SCRUBBING_MODE="semantic" \
      --build-arg DEFAULT_EXCLUSIONS="dev-db-cluster-01,super-secret-service" \
      -t llm-proxy-pii .
    ```

3.  **Run with a custom target**:
    ```bash
    docker run -p 8080:8080 -e TARGET_URL="https://api.openai.com" llm-proxy-pii
    ```

The proxy will be available at `http://localhost:8080`.

## TODO List

- [ ] **OpenAI/Local LLM Support**: Add handlers for `/v1/chat/completions` to support OpenAI, Ollama, vLLM, and other standard APIs.
- [ ] **Streaming Support**: Implement logic to handle chunked/streaming responses (SSE) and de-anonymize data on-the-fly.
- [ ] **Conversation Persistence**: Maintain PII mappings across multiple turns of a conversation for consistent redaction/restoration.
- [ ] **Custom Entity Support**: Allow users to define custom regex or logic for specific sensitive data types.
- [ ] **Comprehensive Testing**: Create a suite of tests to verify PII handling across different edge cases.
