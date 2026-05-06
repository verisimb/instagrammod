FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Coolify default proxy port is often 3000 — match it or set Ports / PORT in the UI konsisten.
ENV PORT=3000
EXPOSE 3000
CMD exec gunicorn --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --timeout 120 app:app
