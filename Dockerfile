FROM python:3.11-slim
WORKDIR /app
COPY ["requirements (1).txt", "requirements.txt"]
RUN pip install --no-cache-dir -r requirements.txt
COPY ["app (2).py", "app.py"]
COPY mailroom.py .
ENV DB_PATH=/tmp/incidents.db
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-7860} --workers 1 --limit-concurrency 200
