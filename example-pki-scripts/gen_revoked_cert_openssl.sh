#!/bin/bash
set -e
SERVER_NAME="$1"
SERVER_DNS="$2"
FILENAME="$3"

echo "Subject: $SERVER_NAME"
echo "Dns: $SERVER_DNS"
echo "Filename: $FILENAME"

if [ -z "$4" ] ; then
  unset KEY_PASS
  read -p "Enter KEY pass: " -s KEY_PASS ; echo
 else
  KEY_PASS="$4"
fi

if [ -z "$5" ] ; then
  unset CA_PASS
  read -p "Enter CA pass: " -s CA_PASS ; echo
 else
  CA_PASS="$5"
fi


cat >tmp_openssl.cnf <<EOL

oid_section = OIDs

[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
default_md = sha256 

[req_distinguished_name]
# empty
# set in command line


[ OIDs ]
sgID=1.2.3.4.5.5

[ v3_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]

EOL

#https://support.quovadisglobal.com/kb/a471/inserting-custom-oids-into-openssl.aspx

openssl genrsa -out $FILENAME.key.tmp 2048
openssl pkcs8 -topk8 -inform pem -in $FILENAME.key.tmp -outform pem -out $FILENAME.key -passout "pass:$KEY_PASS"
#rm -rf $FILENAME.key.tmp

openssl req -new -key $FILENAME.key -out $FILENAME.csr -passin "pass:$KEY_PASS" \
   -subj "$SERVER_NAME" \
   -reqexts v3_req \
   -config <(cat tmp_openssl.cnf \
     <(printf "DNS.1=$SERVER_DNS\nRID.1=sgID"))

openssl ca \
    -in "$FILENAME.csr" \
    -notext \
    -out "$FILENAME-signed.pem" \
    -config "etc/signing-ca.conf" \
    -extensions v3_req \
    -batch \
    -passin "pass:$CA_PASS" \
    -days 720 \
    -extensions server_ext
    

#revocate with signing-ca    
openssl ca -gencrl -crldays 30 -out "$FILENAME.crl" -config etc/signing-ca.conf -passin "pass:$CA_PASS"
openssl ca -revoke "$FILENAME-signed.pem"  -config etc/signing-ca.conf -passin "pass:$CA_PASS"
openssl ca -gencrl -crldays 30 -out "$FILENAME.crl" -config etc/signing-ca.conf -passin "pass:$CA_PASS"


#we do not add the root certificate to the chain
cat "$FILENAME-signed.pem" ca/signing-ca.pem  > $FILENAME.crt.pem
openssl pkcs12 -export -in "$FILENAME.crt.pem" -inkey "$FILENAME.key" -out "$FILENAME.p12" -passin "pass:$KEY_PASS" -passout "pass:$KEY_PASS"
