#!/bin/sh
exec /sbin/setuser elasticsearch /usr/share/elasticsearch/bin/elasticsearch \
     -Des.network.host=$SG_HOST \
     -Dsearchguard.ssl.transport.keystore_filepath="CN=$SG_HOST,OU=SSL,O=Test,L=Test,C=DE-keystore.jks" \
     -Dsearchguard.ssl.http.keystore_filepath="CN=$SG_HOST,OU=SSL,O=Test,L=Test,C=DE-keystore.jks" >> /var/log/elasticsearch.log 2>&1