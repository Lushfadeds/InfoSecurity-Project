# Start with Official Postgres 17 (Debian-based)
# This guarantees we have the correct pg_dump version
FROM postgres:17

# 1. Install Python 3 and Pip
RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

# 2. Install the AWS Lambda Runtime Interface Client (RIC)
# This allows standard Docker images to run as AWS Lambda functions
RUN pip3 install awslambdaric psycopg2-binary --break-system-packages

# 3. Setup the Function Directory
WORKDIR /function
COPY app.py .

# 4. Set the Entrypoint to the AWS Adapter
ENTRYPOINT [ "python3", "-m", "awslambdaric" ]

# 5. Run your handler
CMD [ "app.lambda_handler" ]