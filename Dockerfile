FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280 AS base

WORKDIR /app

COPY pyproject.toml README.md requirements-runtime.lock ./
COPY dlp_proxy ./dlp_proxy
COPY configs ./configs

RUN pip install --no-cache-dir -r requirements-runtime.lock \
    && pip install --no-cache-dir --no-deps .

# Run as non-root.
RUN useradd --uid 10001 --no-create-home dlp
USER 10001

ENV DLP_PORT=8080 \
    DLP_POLICY_PATH=/app/configs/policy.yaml

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s CMD ["python", "-c", "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"DLP_PORT\",\"8080\")}/healthz')"]

CMD ["python", "-m", "dlp_proxy"]
