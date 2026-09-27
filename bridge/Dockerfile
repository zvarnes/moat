# moat bridge: Elastic Security alerts -> DFIR-IRIS. Standard library only (no pip).
FROM python:3.14.7-alpine3.24
RUN adduser -D -u 1000 bridge && mkdir /state && chown 1000:1000 /state
COPY bridge.py /app/bridge.py
USER 1000
ENTRYPOINT ["python3", "-u", "/app/bridge.py"]
