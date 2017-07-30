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
./clean.sh
./gen_root_ca.sh capass changeit
./gen_node_cert.sh 0 changeit capass && ./gen_node_cert.sh 1 changeit capass &&  ./gen_node_cert.sh 2 changeit capass
./gen_revoked_cert_openssl.sh "/CN=revoked.example.com/OU=SSL/O=Test/L=Test/C=DE" "revoked.example.com" "revoked" changeit capass
./gen_node_cert_openssl.sh "/CN=es-node.example.com/OU=SSL/O=Test/L=Test/C=DE" "es-node.example.com" "es-node" changeit capass
./gen_node_cert_openssl.sh "/CN=node-4.example.com/OU=SSL/O=Test/L=Test/C=DE" "node-4.example.com" "node-4" changeit capass
./gen_client_node_cert.sh spock changeit capass
./gen_client_node_cert.sh kirk changeit capass
./gen_client_node_cert.sh logstash changeit capass
./gen_client_node_cert.sh filebeat changeit capass
./gen_client_node_cert.sh kibana changeit capass
#./gen_client_node_cert.sh sgadmin changeit capass
rm -f ./*tmp*