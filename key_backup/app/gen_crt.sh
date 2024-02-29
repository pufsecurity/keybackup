#!/bin/bash

# self signed certificate
#openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj "/CN=CA" -days 36500 -config /home/root/keybackup/openssl_arm/ssl/openssl.cnf

# server certificate
openssl genrsa -out server.key 2048
#openssl req -new -key server.key -out server.csr -subj "/CN=Server" #-config /home/root/keybackup/openssl_arm/ssl/openssl.cnf
openssl req -new -key server.key -out server.csr -subj "/CN=Server" -config /home/root/keybackup/openssl_arm/ssl/openssl.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 36500

# client certificate
openssl genrsa -out client.key 2048
#openssl req -new -key client.key -out client.csr -subj "/CN=Client" #-config /home/root/keybackup/openssl_arm/ssl/openssl.cnf
openssl req -new -key client.key -out client.csr -subj "/CN=Client" -config /home/root/keybackup/openssl_arm/ssl/openssl.cnf
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 36500

# Verify server certificate
openssl verify -CAfile ca.crt server.crt

# Verify client certificate
openssl verify -CAfile ca.crt client.crt

