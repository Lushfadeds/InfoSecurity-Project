
FROM postgres:17

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install awslambdaric psycopg2-binary boto3 --break-system-packages

WORKDIR /function
COPY restore_lambda.py .
    
ENTRYPOINT [ "python3", "-m", "awslambdaric" ]

CMD [ "restore_lambda.lambda_handler" ]