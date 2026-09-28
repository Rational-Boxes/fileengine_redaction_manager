# redaction_manager image.
#
#   podman build -f redaction_manager/Containerfile -t redaction-manager .
#
# Built with THIS directory as context, not the monorepo parent — unlike every
# other service here. That is the point: it reuses no sibling package and must
# not be able to, so the build cannot even see them.
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src/ /app/src/

RUN pip install --no-cache-dir /app

# Loopback only. Publishing this port would defeat the design; run it with
# `--network host` on an operator's session, or reach it through a tunnel.
CMD ["redaction-manager"]
