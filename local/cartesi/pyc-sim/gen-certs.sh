#!/bin/sh
# Throwaway certificates for serve.py (a P-256 one and an RSA-2048 one, valid for 2 days).
# The private keys are test material: do not commit them.
set -eu
openssl ecparam -name prime256v1 -genkey -noout -out ec.key
openssl req -x509 -new -key ec.key -days 2 -subj "/CN=10.0.2.2" -addext "subjectAltName=IP:10.0.2.2,IP:127.0.0.1" -out ec.pem
openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.pem -days 2 -subj "/CN=10.0.2.2" -addext "subjectAltName=IP:10.0.2.2,IP:127.0.0.1"
