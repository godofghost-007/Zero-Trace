FROM node:22-bookworm-slim AS frontend-build
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@10.18.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches
RUN CI=1 pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=3000 \
    FRONTEND_DIST=/app/dist/public \
    ZEROTRACE_DATA_DIR=/data \
    AUDIT_DB_PATH=/data/guard-audit.sqlite \
    DEMO_MODE=false \
    AUTO_CREATE_SCHEMA=false
WORKDIR /app
RUN groupadd --system zerotrace \
    && useradd --system --gid zerotrace --no-create-home --home-dir /app zerotrace
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt
COPY backend ./backend
COPY --from=frontend-build /src/dist/public ./dist/public
RUN mkdir -p /data && chown -R zerotrace:zerotrace /app /data
USER zerotrace
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/api/v1/health', timeout=3)"
CMD ["gunicorn", "--bind=0.0.0.0:3000", "--workers=2", "--threads=4", "--timeout=30", "--access-logfile=-", "--error-logfile=-", "--forwarded-allow-ips=*", "backend:create_app()"]
