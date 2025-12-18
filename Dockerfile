FROM python: 3.11-slim

COPY ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .
COPY . .

EXPOSE 8080
EXPOSE 8080

CMD [ "gunicorn", "--bind", "0.0.0.0:8080", "app_1:app" ]
CMD [ "gunicorn", "--bind", "0.0.0.0:8080", "app_1:app" ]