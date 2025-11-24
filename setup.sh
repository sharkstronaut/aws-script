#!/bin/bash
#
# Automatic setup for graylog, mongodb and opensearch in VPS
# authors: celiabusquets, eliasmuñoz

pip install -r requirements.txt

docker compose up -d

export GRAYLOG_HOST=79.137.73.114
export GRAYLOG_PORT=12201
export GRAYLOG_PROTOCOL=udp
