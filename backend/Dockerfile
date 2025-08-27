# Multi-stage container image to build gilla-auth-api and get it
# installed and running under gunicorn on alpine.


# Stage 1: Build container
FROM python:3.11-slim AS build

ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

RUN \
  apt-get update && \
  apt-get install -y libkrb5-dev krb5-config krb5-user gcc

RUN pip3 install build pip-tools gssapi

COPY setup.cfg setup.py README.md LICENSE ./
COPY gilla_auth/ ./gilla_auth/

RUN pip-compile --output-file requirements.txt setup.cfg
RUN python3 -m build .


# Stage 2: Runtime container
FROM python:3.11-alpine

ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

# Install gunicorn and other runtime dependencies
RUN \
  apk add --no-cache --virtual .build-deps gcc musl-dev krb5-dev krb5 libffi-dev

# Copy the requirements.txt file from the build stage first, it will change less often than the wheel
COPY --from=build /build/requirements.txt .
RUN pip3 install -r requirements.txt && \
    pip3 install gunicorn

# Copy the built wheel from the build stage
COPY --from=build /build/dist/gilla*.whl .

# Install the wheel
RUN pip3 install gilla*.whl && \
    rm gilla*.whl && \
    apk del .build-deps krb5-dev

# Create a non-root user
RUN adduser -DS -s /sbin/nologin gilla gilla

USER gilla

EXPOSE 5000

ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "gilla_auth.api:app"]
