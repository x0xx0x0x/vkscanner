FROM mcr.microsoft.com/playwright/python:v1.49.1-jammy

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
COPY wheels /tmp/wheels
RUN pip install --default-timeout=1000 --retries=10 --no-cache-dir --find-links=/tmp/wheels -r requirements.txt

# Pre-download NLTK data
RUN python -c "import nltk; nltk.download('vader_lexicon', quiet=True)" || true

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
