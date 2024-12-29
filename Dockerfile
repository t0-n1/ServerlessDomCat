FROM python:3.10-slim
WORKDIR /app
RUN mkdir results
RUN apt update
RUN pip install --upgrade pip
RUN pip install --no-cache-dir playwright requests shodan
RUN playwright install --with-deps firefox
COPY template.html .
COPY serverlessdomcat.py .
ENTRYPOINT ["python", "-u", "serverlessdomcat.py"]
