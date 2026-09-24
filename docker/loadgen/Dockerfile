FROM python:3.12-slim
COPY server.py /server.py
ENV BURN_MS=100 PORT=8080
EXPOSE 8080
CMD ["python", "-u", "/server.py"]