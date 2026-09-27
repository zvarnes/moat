# One-shot helper image: generates certs, sets passwords, bootstraps Fleet + detections.
FROM alpine:3.24.2
RUN apk add --no-cache bash curl jq openssl gettext ca-certificates
COPY scripts/ /setup/
COPY templates/ /setup/templates/
RUN chmod +x /setup/*.sh
ENTRYPOINT ["/bin/bash"]
