FROM python:3.11-slim
RUN pip install fastapi uvicorn httpx presidio-analyzer presidio-anonymizer spacy pytest pytest-asyncio && \
    python -m spacy download en_core_web_lg

# Build argument for exclusions (comma-separated)
ARG DEFAULT_EXCLUSIONS=""
ENV DEFAULT_EXCLUSIONS=$DEFAULT_EXCLUSIONS

# Build argument for mode (semantic or generic)
ARG SCRUBBING_MODE="generic"
ENV SCRUBBING_MODE=$SCRUBBING_MODE

# Build argument for analyzer type (presidio, pattern, or both)
ARG ANALYZER_TYPE="both"
ENV ANALYZER_TYPE=$ANALYZER_TYPE

# Target LLM provider (default: Google Cloud Code)
ENV TARGET_URL="https://cloudcode-pa.googleapis.com"

COPY proxy.py .
CMD ["python", "proxy.py"]
