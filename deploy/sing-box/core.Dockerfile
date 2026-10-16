ARG SINGBOX_IMAGE=ghcr.io/sagernet/sing-box:v1.14.3
FROM ${SINGBOX_IMAGE} AS singbox-core
FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=singbox-core /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY scripts/sing-box-supervisor.py /usr/local/bin/sing-box-supervisor.py

ENTRYPOINT ["python3", "/usr/local/bin/sing-box-supervisor.py"]
