#!/bin/bash

CONFIG_FILE="keybackup.conf"

while IFS='=' read -r name value; do
    if [[ $name != \#* && $name != "" ]]; then
        name=$(echo $name | tr -d '[:space:]')
            value=$(echo ${value//\"/})
            value=$(echo $value | tr -d '[:space:]')
            #echo "$name = $value"
    fi
    if [[ $name == "SERVER_IP" ]]; then
        SERVER_IP=$value
    fi
    if [[ $name == "SERVER_PORT" ]]; then
        SERVER_PORT=$value
    fi
    if [[ $name == "CLIENT_KEY_PASSWD" ]]; then
        CLIENT_KEY_PASSWD=$value
    fi
done < "$CONFIG_FILE"

if [[ $SERVER_IP != "" ]] && [[ $SERVER_PORT != "" ]] && [[ $CLIENT_KEY_PASSWD != "" ]]; then
    echo ./client -a $SERVER_IP -p $SERVER_PORT -c $CLIENT_KEY_PASSWD
    ./client -a $SERVER_IP -p $SERVER_PORT -c $CLIENT_KEY_PASSWD
else
    echo SERVER_IP = $SERVER_IP
    echo SERVER_PORT = $SERVER_PORT
    echo CLIENT_KEY_PASSWD = $CLIENT_KEY_PASSWD
    exit 1
fi

