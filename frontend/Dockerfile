FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY daftgila ./daftgila/

EXPOSE 8000

CMD ["gunicorn", \
    "--bind", "0.0.0.0:8000", \
    "--workers", "4", \
    "--timeout", "120", \
    "daftgila.web:app"]


# The end.
