FROM python:3.12.4-slim@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
RUN useradd -r appuser
USER appuser
RUN pip install flask==2.3.2
CMD ["python", "app.py"]
