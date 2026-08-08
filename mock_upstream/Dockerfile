FROM python:3.13-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6

WORKDIR /app

COPY requirements.lock .

RUN pip install --no-cache-dir -r requirements.lock

COPY server.py .

USER 10001

EXPOSE 9000

CMD ["python", "server.py"]
