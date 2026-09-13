FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN adduser --disabled-password --gecos "" --uid 10001 lottery

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

USER lottery
EXPOSE 5000

# Single worker/thread process: the draw thread + in-memory rate limiter
# must live in exactly one process.
CMD ["python", "-c", "import threading, app; threading.Thread(target=app.background_loop, daemon=True).start(); from waitress import serve; serve(app.app, host='0.0.0.0', port=5000, threads=4)"]
