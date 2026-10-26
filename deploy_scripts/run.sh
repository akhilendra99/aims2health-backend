#!/usr/bin/env bash

cd /home/ubuntu/aims2health_backend
# Install project dependencies
npm install
npm run build
npm run build


sudo pm2 delete aims2health_backend
# Start the production server with PM2
sudo pm2 start npm --name "aims2health_backend" -- start
 
