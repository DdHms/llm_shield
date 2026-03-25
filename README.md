# LLM Privacy Proxy

A privacy-preserving proxy for LLMs (Local and Remote) that automatically identifies and redacts Personal Identifiable Information (PII) from prompts before they reach the provider, and restores the original data in the model's response.

## Features

- **PII Detection & Redaction**: Uses Microsoft Presidio and Spacy to identify PII (names, emails, locations, etc.) in outgoing prompts.
- **Unique Placeholder Mapping**: Replaces PII with identifiable placeholders (e.g., `<PERSON_0>`, `<EMAIL_ADDRESS_1>`) to maintain context for the LLM.
- **Response De-anonymization**: Automatically replaces placeholders in the LLM's response with the original sensitive data, ensuring the user sees the complete information while the provider never does.
- **Gemini Internal API Support**: Currently configured to intercept and modify `v1internal` Gemini Content requests.

## How It Works

1.  **Intercept**: The proxy captures incoming POST requests.
2.  **Analyze & Scrub**: It parses the request body, identifies PII using the `presidio-analyzer`, and replaces it with unique placeholders.
3.  **Map**: A temporary mapping of `placeholder -> original_value` is stored for the duration of the request.
4.  **Forward**: The scrubbed request is forwarded to the target LLM provider (e.g., Google Cloud Code endpoint).
5.  **Restore**: When the response arrives, the proxy recursively scans the JSON for placeholders and replaces them with the original values from the mapping.

## Setup & Run

### Prerequisites

- Docker installed on your system.

### Building and Running

1.  **Build the Docker image**:
    ```bash
    docker build -t llm-proxy-pii .
    ```

2.  **Run the container**:
    ```bash
    docker run -p 8080:8080 llm-proxy-pii
    ```

The proxy will be available at `http://localhost:8080`.

## TODO List

- [ ] **OpenAI/Local LLM Support**: Add handlers for `/v1/chat/completions` to support OpenAI, Ollama, vLLM, and other standard APIs.
- [ ] **Streaming Support**: Implement logic to handle chunked/streaming responses (SSE) and de-anonymize data on-the-fly.
- [ ] **Conversation Persistence**: Maintain PII mappings across multiple turns of a conversation for consistent redaction/restoration.
- [ ] **Custom Entity Support**: Allow users to define custom regex or logic for specific sensitive data types (e.g., internal project names).
- [ ] **Configuration Layer**: Move `TARGET_URL` and other settings to environment variables or a config file.
- [ ] **Comprehensive Testing**: Create a suite of tests to verify PII handling across different edge cases and LLM providers.
