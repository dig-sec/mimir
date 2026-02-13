FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install -e .

EXPOSE 8000

CMD ["uvicorn", "mimir.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
