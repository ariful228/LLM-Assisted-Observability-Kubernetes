FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY backend ./backend
COPY knowledge ./knowledge
COPY frontend ./frontend
COPY monitoring ./monitoring

RUN mkdir -p data/certs
ENV EXTERNAL_MODE=simulated \
    LLM_PROVIDER=mock \
    DATA_DIR=/app/data \
    KNOWLEDGE_DIR=/app/knowledge

EXPOSE 8199

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8199"]