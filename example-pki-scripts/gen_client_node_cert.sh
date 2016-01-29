#!/bin/bash
set -e
CLIENT_NAME=$1
KS_PASS=$2
CA_PASS=$3
rm -f $CLIENT_NAME-keystore.jks
rm -f $CLIENT_NAME.csr
rm -f $CLIENT_NAME-signed.pem

echo Generating keystore and certificate for node $CLIENT_NAME

keytool -genkey \
        -alias     $CLIENT_NAME \
        -keystore  $CLIENT_NAME-keystore.jks \
        -keyalg    RSA \
        -keysize   2048 \
        -validity  712 \
        -keypass $KS_PASS \
        -storepass $KS_PASS \
        -dname "CN=$CLIENT_NAME, OU=client, O=client, L=Test, C=DE"

echo Generating certificate signing request for node $CLIENT_NAME

keytool -certreq \
        -alias      $CLIENT_NAME \
        -keystore   $CLIENT_NAME-keystore.jks \
        -file       $CLIENT_NAME.csr \
        -keyalg     rsa \
        -keypass $KS_PASS \
        -storepass $KS_PASS \
        -dname "CN=$CLIENT_NAME, OU=client, O=client, L=Test, C=DE"

echo Sign certificate request with CA
openssl ca \
    -in $CLIENT_NAME.csr \
    -notext \
    -out $CLIENT_NAME-signed.pem \
    -config etc/signing-ca.conf \
    -extensions v3_req \
    -batch \
	-passin pass:$CA_PASS \
	-extensions server_ext 

echo "Import back to keystore (including CA chain)"

cat ca/chain-ca.pem $CLIENT_NAME-signed.pem | keytool \
    -importcert \
    -keystore $CLIENT_NAME-keystore.jks \
    -storepass $KS_PASS \
    -noprompt \
    -alias $CLIENT_NAME

keytool -importkeystore -srckeystore $CLIENT_NAME-keystore.jks -srcstorepass $KS_PASS -srcstoretype JKS -deststoretype PKCS12 -deststorepass $KS_PASS -destkeystore $CLIENT_NAME-keystore.p12

echo All done for $CLIENT_NAME
	