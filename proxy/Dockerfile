FROM --platform=amd64 ubuntu:22.04

RUN apt -y update
RUN apt install build-essential gcc git -y &&\
    apt upgrade -y
RUN apt update && \
    apt install -y curl tar ca-certificates

ENV GO_VERSION 1.20
RUN curl -L https://golang.org/dl/go$GO_VERSION.linux-amd64.tar.gz -o  go$GO_VERSION.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz && rm -f  go$GO_VERSION.linux-amd64.tar.gz
ENV PATH /usr/local/go/bin:$PATH
ENV GOROOT /usr/local/go

ADD . /go/src/github.com/sklrsn/postgres-proxy/proxy/
WORKDIR /go/src/github.com/sklrsn/postgres-proxy/proxy/

RUN go mod download

RUN mkdir -p /opt/bin
RUN go build -o /opt/bin/proxy .
RUN chmod +x /opt/bin/proxy

COPY ./certs/ca-crt.pem /usr/local/share/ca-certificates
COPY ./certs/proxy-crt.pem /opt/bin/
COPY ./certs/proxy-key.pem /opt/bin/
RUN update-ca-certificates

EXPOSE 8989
CMD [ "/opt/bin/proxy" ]