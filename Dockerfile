FROM python: 3.11-slim

COPY ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN python3 -m pip install --no-cache-dir -r requirements.txt

RUN python3 -m pip install gunicorn

COPY . .

EXPOSE 8080

CMD [ "python3", "-m", "gunicorn", "--bind", "0.0.0.0:8080", "app_1:app" ]