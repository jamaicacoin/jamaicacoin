FROM debian:stretch
LABEL maintainer="JamaicaCoin Developers <dev@jamaicacoin.org>"
LABEL description="Dockerised JamaicaCoinCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
