FROM python:3.11-slim
RUN pip install fastapi uvicorn httpx presidio-analyzer presidio-anonymizer spacy && \
    python -m spacy download en_core_web_lg

# Build argument for exclusions (comma-separated)
ARG DEFAULT_EXCLUSIONS=""
ENV DEFAULT_EXCLUSIONS=$DEFAULT_EXCLUSIONS

# Build argument for mode (semantic or generic)
ARG SCRUBBING_MODE="generic"
ENV SCRUBBING_MODE=$SCRUBBING_MODE

# Target LLM provider (default: Google Cloud Code)
ENV TARGET_URL="https://cloudcode-pa.googleapis.com"

COPY proxy.py .
CMD ["python", "proxy.py"]
