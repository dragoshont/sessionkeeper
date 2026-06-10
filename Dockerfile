# sessionkeeper — stateless refresh engine for custom-login sessions.
#
# Runtime is Python-stdlib-only (no pip deps), so the image is just python-slim
# + the source. Multi-arch (python:slim is published for amd64 + arm64).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SESSIONKEEPER_PORT=9090

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# Install the package itself (no third-party deps pulled).
RUN pip install --no-cache-dir . \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin sessionkeeper

USER sessionkeeper
EXPOSE 9090

# Healthy = the metrics/health server is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('SESSIONKEEPER_PORT','9090')+'/healthz', timeout=3).status==200 else 1)"

ENTRYPOINT ["python", "-m", "sessionkeeper"]
