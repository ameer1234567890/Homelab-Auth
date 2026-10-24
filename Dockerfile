FROM python:3.13-alpine
RUN adduser -D -u 10001 app && mkdir -p /data && chown app /data
WORKDIR /app
COPY app.py .
COPY static ./static
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
VOLUME /data
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/_auth/healthz')"
CMD ["python", "app.py"]
