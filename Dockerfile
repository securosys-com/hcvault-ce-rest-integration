## DOCKERHUB DOCKERFILE ##
FROM debian:stable-slim
VOLUME ["/tmp", "/opt/app/" ]
ENV VAULT_ADDR='http://0.0.0.0:8200'
ENV VAULT_API_ADDR='http://0.0.0.0:8200'
ENV VAULT_ADDRESS='http://0.0.0.0:8200'
#RUN yum -y update && yum -y install git curl vim-common jq
#ARG DEPENDENCY=install
COPY bin /opt/app
RUN \
  apt-get -y update && \
  apt-get -y install ca-certificates && \
  apt-get clean
EXPOSE 8200
EXPOSE 8201
ENTRYPOINT ["./opt/app/vault","server", "-config=/etc/app/config/config.hcl"]
