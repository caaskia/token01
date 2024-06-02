#!/bin/bash

response=$(curl -s -H "Content-Type: application/json" -X POST -d '{"username":"test","password":"test"}' http://localhost:8000/login)
access_token=$(echo $response | jq -r .access_token)
refresh_token=$(echo $response | jq -r .refresh_token)