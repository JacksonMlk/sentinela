FROM python:3.11-slim

# WeasyPrint + Prowler system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # WeasyPrint
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    shared-mime-info \
    # Prowler (optional — installed separately via pip, needs these for some checks)
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Prowler is optional — install if needed
# RUN pip install --no-cache-dir prowler

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
