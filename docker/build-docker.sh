#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-jamaicacoinpay/jamaicacoind-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/jamaicacoind docker/bin/
cp $BUILD_DIR/src/jamaicacoin-cli docker/bin/
cp $BUILD_DIR/src/jamaicacoin-tx docker/bin/
strip docker/bin/jamaicacoind
strip docker/bin/jamaicacoin-cli
strip docker/bin/jamaicacoin-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
