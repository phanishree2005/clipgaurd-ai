FROM python:3.11-slim

WORKDIR /app

# Install YARA dependencies and build tools
RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download presidio NLP model (spacy en_core_web_lg) - using small for memory efficiency in demo
RUN python -m spacy download en_core_web_sm

COPY . .

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
