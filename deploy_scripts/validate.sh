#!/usr/bin/env bash

# Wait for 10 seconds###
sleep 10

# Check if the service is running on port 8090
nc -zv 127.0.0.1 9000
