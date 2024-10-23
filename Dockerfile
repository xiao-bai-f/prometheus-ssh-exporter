ARG ARCH="amd64"
ARG OS="linux"
#FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
FROM python:3-slim

WORKDIR /bin

ARG ARCH="amd64"
ARG OS="linux"

ADD .build/${OS}-${ARCH}/ssh-exporter /bin/
EXPOSE      9030
USER        nobody
ENTRYPOINT  [ "/bin/ssh-exporter" ]
