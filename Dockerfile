FROM python:3.12

WORKDIR /app

# Build argument for analyzer type (presidio, pattern, or both)
ARG ANALYZER_TYPE="pattern"
ENV ANALYZER_TYPE=$ANALYZER_TYPE

# Install core dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install heavy dependencies ONLY if ANALYZER_TYPE is not "pattern"
RUN if [ "$ANALYZER_TYPE" != "pattern" ]; then \
        pip install --no-cache-dir presidio-analyzer presidio-anonymizer spacy && \
        python -m spacy download en_core_web_lg; \
    fi

# Build argument for exclusions (comma-separated)
ARG DEFAULT_EXCLUSIONS=""
ENV DEFAULT_EXCLUSIONS=$DEFAULT_EXCLUSIONS

# Build argument for mode (semantic or generic)
ARG SCRUBBING_MODE="generic"
ENV SCRUBBING_MODE=$SCRUBBING_MODE

# Target LLM provider (default: Google Cloud Code)
ENV TARGET_URL="https://cloudcode-pa.googleapis.com"

# Copy all source files
COPY src/ ./src/

# Set PYTHONPATH to include src directory so internal imports work
ENV PYTHONPATH="/app/src"

CMD ["python", "src/proxy.py"]
