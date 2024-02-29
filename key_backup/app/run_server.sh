#!/bin/bash

CONFIG_FILE="keybackup.conf"

while IFS='=' read -r name value; do
    if [[ $name != \#* && $name != "" ]]; then
        name=$(echo $name | tr -d '[:space:]')
            value=$(echo ${value//\"/})
            value=$(echo $value | tr -d '[:space:]')
            #echo "$name = $value"
    fi
    if [[ $name == "SERVER_ENABLE" ]]; then
        SERVER_ENABLE=$value
    fi
    if [[ $name == "SERVER_PORT" ]]; then
        SERVER_PORT=$value
    fi
    if [[ $name == "SERVER_KEY_PATH" ]]; then
        SERVER_KEY_PATH=$value
    fi
done < "$CONFIG_FILE"

if [[ $SERVER_ENABLE == "1" ]] && [[ $SERVER_PORT != "" ]] && [[ $SERVER_KEY_PATH != "" ]]; then
    echo ./server -p $SERVER_PORT -d $SERVER_KEY_PATH -m
    ./server -p $SERVER_PORT -d $SERVER_KEY_PATH -m
else
    echo SERVER_ENABLE = $SERVER_ENABLE
    echo SERVER_PORT = $SERVER_PORT
    echo SERVER_KEY_PATH = $SERVER_KEY_PATH
    exit 1
fi

