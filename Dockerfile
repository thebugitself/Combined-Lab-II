# ───────────────────────────────────────────────
#  ID-Networkers Combined Lab 2: The XML Gateway
# ───────────────────────────────────────────────
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /lab

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app/ app/

# Plant the flag 🚩
RUN echo "FLAG{XXE_AND_JWT_CH41N3D_ATT4CK_SUCC3SS}" > /flag.txt && \
    chmod 444 /flag.txt

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
