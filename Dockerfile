FROM python:3.11-slim
RUN pip install fastapi uvicorn httpx presidio-analyzer presidio-anonymizer spacy && \
    python -m spacy download en_core_web_lg
COPY proxy.py .
CMD ["python", "proxy.py"]
