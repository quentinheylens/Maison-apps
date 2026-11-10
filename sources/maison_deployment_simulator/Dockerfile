FROM python:3.12.16-alpine3.24@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7
WORKDIR /app
COPY gateway /app/gateway
COPY maintenance /app/maintenance
COPY yaml /app/yaml
COPY PyYAML-LICENSE /app/PyYAML-LICENSE
COPY installation-profile.json /app/installation-profile.json
COPY healthcheck.py /app/healthcheck.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MAISON_ROLE=deployment
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["python3", "-m", "maintenance.entrypoint", "healthcheck"]
ENTRYPOINT ["python3", "-m", "maintenance.entrypoint", "deployment"]
