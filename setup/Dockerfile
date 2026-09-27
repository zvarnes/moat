# One-shot helper image: generates certs, sets passwords, bootstraps Fleet + detections.
FROM alpine:3.24.2
RUN apk add --no-cache bash curl jq openssl gettext ca-certificates python3
# Sigma toolchain in its own venv. --require-hashes: pip refuses any file whose hash
# isn't in the lock (regenerate it from requirements-sigma.in with pip-compile).
COPY requirements-sigma.txt /tmp/requirements-sigma.txt
RUN python3 -m venv /opt/sigma \
 && /opt/sigma/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      -r /tmp/requirements-sigma.txt \
 && rm /tmp/requirements-sigma.txt
COPY scripts/ /setup/
COPY templates/ /setup/templates/
RUN chmod +x /setup/*.sh
ENTRYPOINT ["/bin/bash"]
