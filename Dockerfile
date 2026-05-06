FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

ENV PORT=5050
EXPOSE 5050
CMD exec gunicorn --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --timeout 120 app:app
