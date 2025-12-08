#!/bin/bash

set -e

echo "Building Linux binary using Docker..."

docker build -f Dockerfile.build -t httpcap-builder .
docker create --name httpcap-temp httpcap-builder
docker cp httpcap-temp:/build/httpcap-linux-amd64 .
docker rm httpcap-temp

echo "✓ Build complete: httpcap-linux-amd64"
