#!/bin/sh

echo "Wait a few seconds ..."
sleep 15

while :
do
    #openssl s_client -servername sgssl-0.example.com -tls1_2 -connect sgssl-0.example.com:9200  -CAfile "$ES_CONF_DIR/chain-ca.pem"  -verify_return_error -cert "$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.all.pem" &
	#openssl s_client -servername sgssl-0.example.com -tls1_2 -connect sgssl-0.example.com:9200  -CAfile "$ES_CONF_DIR/chain-ca.pem"  -verify_return_error -cert "$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.crtfull.pem" -key "$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.key.pem" &

	echo "--------------------- WGET Combined ------------"
	wget -O- --ca-cert="$ES_CONF_DIR/chain-ca.pem" --certificate="$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.all.pem" https://sgssl-0.example.com:9200/_searchguard/sslinfo 	
	echo ""
	echo "--------------------- WGET Single ------------"
	wget -O- --ca-cert="$ES_CONF_DIR/chain-ca.pem" --certificate="$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.crtfull.pem" --private-key="$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.key.pem" https://sgssl-0.example.com:9200/_cluster/health
    echo ""
    echo "--------------------- CURL Combined ------------"
	curl -Ss https://sgssl-0.example.com:9200/_searchguard/sslinfo -E "$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.all.pem" --cacert "$ES_CONF_DIR/chain-ca.pem"
	echo ""
	echo "--------------------- CURL Single ------------"
	curl -Ss https://sgssl-0.example.com:9200/_cluster/health -E "$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.crtfull.pem" --key "$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.key.pem" --cacert "$ES_CONF_DIR/chain-ca.pem"
	echo ""
	python3 /esclient.py
	echo ""
	#curator --host sgssl-0.example.com --port 9200 --use_ssl --client-cert "$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.crtfull.pem" --client-key "$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.key.pem" --certificate "$ES_CONF_DIR/chain-ca.pem" show indices --all-indices
	#curator --host sgssl-0.example.com --port 9200 --use_ssl --client-cert "$ES_CONF_DIR/CN=picard,OU=client,O=client,L=Test,C=DE.all.pem" --certificate "$ES_CONF_DIR/chain-ca.pem" show indices --all-indices
	sleep 10
done