FROM python:3.8.5-alpine3.11

WORKDIR /app

COPY . /app

RUN pip3 --no-cache-dir install -r requirements.txt

ENTRYPOINT python app.py