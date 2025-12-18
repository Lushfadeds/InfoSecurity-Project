FROM python: 3.11-slim

COPY ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD [ "gunicorn", "--bind", "0.0.0.0:8080", "app_1:app" ]