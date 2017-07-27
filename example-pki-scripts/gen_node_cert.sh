#!/bin/bash
#########################
# 'dname' and 'ext san' have to specified on two location in this file  
# For the meaning of oid:1.2.3.4.5.5 see:
#    https://github.com/floragunncom/search-guard-docs/blob/master/architecture.md
#    https://github.com/floragunncom/search-guard-docs/blob/master/installation.md
#########################

set -e
NODE_NAME=node-$1

if [ -z "$3" ] ; then
  unset CA_PASS KS_PASS
  read -p "Enter CA pass: " -s CA_PASS ; echo
  read -p "Enter Keystore pass: " -s KS_PASS ; echo
 else
  KS_PASS=$2
  CA_PASS=$3
fi

rm -f $NODE_NAME-keystore.jks
rm -f $NODE_NAME.csr
rm -f $NODE_NAME-signed.pem

BIN_PATH="keytool"

if [ ! -z "$JAVA_HOME" ]; then
    BIN_PATH="$JAVA_HOME/bin/keytool"
fi

echo Generating keystore and certificate for node $NODE_NAME

if [ -z "$DN" ]; then
   DN="CN=$NODE_NAME.example.com, OU=SSL, O=Test, L=Test, C=DE"
fi



"$BIN_PATH" -genkey \
        -alias     $NODE_NAME \
        -keystore  $NODE_NAME-keystore.jks \
        -keyalg    RSA \
        -keysize   2048 \
        -validity  712 \
        -sigalg SHA256withRSA \
        -keypass $KS_PASS \
        -storepass $KS_PASS \
        -dname "$DN" \
        -ext san=dns:$NODE_NAME.example.com,dns:localhost,ip:127.0.0.1,oid:1.2.3.4.5.5 
        
#oid:1.2.3.4.5.5 denote this a server node certificate for search guard

echo Generating certificate signing request for node $NODE_NAME

"$BIN_PATH" -certreq \
        -alias      $NODE_NAME \
        -keystore   $NODE_NAME-keystore.jks \
        -file       $NODE_NAME.csr \
        -keyalg     rsa \
        -keypass $KS_PASS \
        -storepass $KS_PASS \
        -dname "$DN" \
        -ext san=dns:$NODE_NAME.example.com,dns:localhost,ip:127.0.0.1,oid:1.2.3.4.5.5
        
#oid:1.2.3.4.5.5 denote this a server node certificate for search guard

echo Sign certificate request with CA
openssl ca \
    -in $NODE_NAME.csr \
    -notext \
    -out $NODE_NAME-signed.pem \
    -config etc/signing-ca.conf \
    -extensions v3_req \
    -batch \
	-passin pass:$CA_PASS \
	-extensions server_ext 

echo "Import back to keystore (including CA chain)"

cat ca/chain-ca.pem $NODE_NAME-signed.pem | "$BIN_PATH" \
    -importcert \
    -keystore $NODE_NAME-keystore.jks \
    -storepass $KS_PASS \
    -noprompt \
    -alias $NODE_NAME
    
"$BIN_PATH" -importkeystore -srckeystore $NODE_NAME-keystore.jks -srcstorepass $KS_PASS -srcstoretype JKS -deststoretype PKCS12 -deststorepass $KS_PASS -destkeystore $NODE_NAME-keystore.p12

openssl pkcs12 -in "$NODE_NAME-keystore.p12" -out "$NODE_NAME.key.pem" -nocerts -nodes -passin pass:$KS_PASS
openssl pkcs12 -in "$NODE_NAME-keystore.p12" -out "$NODE_NAME.crt.pem" -nokeys -passin pass:$KS_PASS

echo All done for $NODE_NAME
	
