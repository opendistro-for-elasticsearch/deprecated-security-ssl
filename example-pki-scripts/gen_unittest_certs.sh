#!/bin/bash
OPENSSL_VER="$(openssl version)"

if [[ $OPENSSL_VER == *"0.9"* ]]; then
	echo "Your OpenSSL version is too old: $OPENSSL_VER"
	echo "Please install version 1.0.1 or later"
	exit -1
else
    echo "Your OpenSSL version is: $OPENSSL_VER"
fi

set -e
rm -f node-untspec5-keystore*
./gen_node_cert_openssl.sh "/emailAddress=unt@tst.com/CN=node-untspec5.example.com/OU=SSL/O=Te\, st/L=Test/C=DE" "node-untspec5-keystore" "node-untspec5-keystore" changeit capass
rm -f node-untspec6-keystore*
./gen_node_cert_openssl.sh "/emailAddress=unt@xxx.com/CN=node-untspec6.example.com/OU=SSL/O=Te\, st/L=Test/C=DE" "node-untspec6-keystore" "node-untspec6-keystore" changeit capass