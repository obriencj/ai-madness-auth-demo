# Multi-stage container image to build gilla-auth-api and get it
# installed and running under gunicorn on alpine.

FROM python:3.11-slim AS build

ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

COPY setup.cfg setup.py README.md ./
COPY gilla_auth/ ./gilla_auth/

RUN \
  pip3 install build && \
  python3 -m build .

FROM python:3.11-alpine

ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

# Install gunicorn and other runtime dependencies
RUN \
  apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev && \
  pip3 install gunicorn && \
  apk del .build-deps

# Copy the built wheel from the build stage
COPY --from=build /build/dist/gilla*.whl .

# Install the wheel
RUN pip3 install gilla*.whl && \
    rm gilla*.whl

# Create a non-root user
RUN adduser -DS -s /sbin/nologin gilla gilla

USER gilla

EXPOSE 5000

ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "gilla_auth.api:app"]
