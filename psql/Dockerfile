FROM ubuntu:22.04

WORKDIR /psql-client

RUN apt-get update -y

RUN apt-get install -y postgresql-client ca-certificates

COPY ./certs/ca-crt.pem /usr/local/share/ca-certificates
COPY ./certs/psql-crt.pem /etc/ssl/
COPY ./certs/psql-key.pem /etc/ssl/private/

RUN chmod 600 /etc/ssl/private/psql-key.pem
RUN update-ca-certificates

COPY entrypoint.sh .

CMD [ "/psql-client/entrypoint.sh" ]