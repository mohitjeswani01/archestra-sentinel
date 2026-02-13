#!/bin/bash
echo "Initializing Archestra Sentinel Environment..."
docker-compose down
docker-compose pull
docker-compose up -d postgres
echo "Waiting for Database..."
sleep 5
docker-compose up -d
echo "Archestra Sentinel is now LIVE."