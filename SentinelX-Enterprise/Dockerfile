FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY database database
COPY service_common.py .
COPY sentinelx-backend sentinelx-backend
COPY demolab/backend demolab/backend
ENV PYTHONUNBUFFERED=1

