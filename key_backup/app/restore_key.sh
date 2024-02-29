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
    if [[ $name == "CLIENT_IP" ]]; then
        CLIENT_IP=$value
    fi
    if [[ $name == "SERVER_PORT" ]]; then
        SERVER_PORT=$value
    fi
    if [[ $name == "CLIENT_KEY_PASSWD" ]]; then
        CLIENT_KEY_PASSWD=$value
    fi
done < "$CONFIG_FILE"

if [[ $SERVER_IP != "" ]] && [[ $CLIENT_IP != "" ]] && [[ $SERVER_PORT != "" ]] && [[ $CLIENT_KEY_PASSWD != "" ]]; then
    #echo SERVER_IP = $SERVER_IP
    #echo CLIENT_IP = $CLIENT_IP
    #echo SERVER_PORT = $SERVER_PORT
    #echo CLIENT_KEY_PASSWD = $CLIENT_KEY_PASSWD
    ping -A -c 2 -w 1 $CLIENT_IP &> /dev/null
    CLIENT_MAC=`cat /proc/net/arp | grep $CLIENT_IP | awk '{print $4}' | tr -d ':'`
    if [[ $? != "0" ]]; then
        echo $CLIENT_IP no reply!
        exit 1
    fi
    if [[ $CLIENT_MAC == "" ]]; then
        IF=`ip route | grep $CLIENT_IP | awk '{print $3}'`
        CLIENT_MAC=`ip link show $IF | awk 'NR==2 {print $2}' | tr -d ':'`
    fi
    #echo CLIENT_MAC = $CLIENT_MAC
    echo ./client -a $SERVER_IP -p $SERVER_PORT -c $CLIENT_KEY_PASSWD -m $CLIENT_MAC -r
    ./client -a $SERVER_IP -p $SERVER_PORT -c $CLIENT_KEY_PASSWD -m $CLIENT_MAC -r
else
    echo SERVER_IP = $SERVER_IP
    echo CLIENT_IP = $CLIENT_IP
    echo SERVER_PORT = $SERVER_PORT
    echo CLIENT_KEY_PASSWD = $CLIENT_KEY_PASSWD
    exit 1
fi

