#!/bin/bash

read -p "Please enter Tenant Or Chimney Environment Name: " TenantName

if [ -z "$TenantName" ]; then
    echo "Name is mandatory"
    exit 1
fi

openssl req -new -newkey rsa:2048 -nodes -sha256 -keyout "${TenantName}_private_enc.pem" -x509 -days 730 -out "${TenantName}_public_enc.crt" -subj "/C=US/ST=NY/L=NY/O=Chimney/OU=Engineering/CN=${TenantName}.enc.chimney.io"
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "${TenantName}_private_sig.pem" -out "${TenantName}_public_sig.crt" -days 730 -subj "/C=US/ST=NY/L=NY/O=Chimney/OU=Engineering/CN=${TenantName}.sig.chimney.io"