
FROM postgres:12

COPY ./certs/postgres-crt.pem /var/lib/postgresql/server.crt
COPY ./certs/postgres-key.pem /var/lib/postgresql/server.key
COPY ./certs/ca-crt.pem /var/lib/postgresql/root.crt

RUN chown postgres:postgres /var/lib/postgresql/server.crt
RUN chmod 600 /var/lib/postgresql/server.key
RUN chown postgres:postgres /var/lib/postgresql/server.key
RUN chown postgres:postgres /var/lib/postgresql/root.crt

COPY ./postgresql.conf /var/lib/postgresql/data/
COPY ./pg_hba.conf /var/lib/postgresql/data/
RUN chown postgres:postgres /var/lib/postgresql/data/postgresql.conf
RUN chown postgres:postgres /var/lib/postgresql/data/pg_hba.conf

EXPOSE 5432