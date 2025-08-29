
# Stage 1: Build client
FROM python:3.11-slim AS build-client

ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

RUN pip3 install build

COPY client/ ./client
RUN python3 -m build  -o /build/dist/ client


# Stage 2: Build frontend
FROM python:3.11-slim AS build-frontend

ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

RUN pip3 install build

COPY frontend/ ./frontend
RUN python3 -m build -o /build/dist/ frontend


# Stage 2: Runtime container
FROM python:3.11-alpine

ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

RUN pip install --no-cache-dir gunicorn


COPY --from=build-client /build/dist/daftgila_client-*.whl .

# Install the wheel
RUN pip3 install daftgila_client-*.whl && \
    rm *.whl

COPY --from=build-frontend /build/dist/daftgila_web-*.whl .

# Install the wheel
RUN pip3 install daftgila_web-*.whl && \
    rm *.whl
    
# Create a non-root user
RUN adduser -DS -s /sbin/nologin daftgila daftgila

USER daftgila

EXPOSE 8000

CMD ["gunicorn", \
    "--bind", "0.0.0.0:8000", \
    "--workers", "4", \
    "--timeout", "120", \
    "daftgila.web:app"]


# The end.
