FROM python:3.12-alpine3.22@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322
WORKDIR /app
COPY gateway /app/gateway
COPY maintenance /app/maintenance
COPY yaml /app/yaml
COPY PyYAML-LICENSE /app/PyYAML-LICENSE
COPY installation-profile.json /app/installation-profile.json
COPY healthcheck.py /app/healthcheck.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MAISON_ROLE=diagnostic
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["python3", "/app/healthcheck.py"]
ENTRYPOINT ["python3", "-m", "maintenance.entrypoint", "diagnostic"]
