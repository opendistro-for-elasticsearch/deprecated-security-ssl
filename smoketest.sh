#!/bin/bash
killall -9 java
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

ES_VERSION=6.5.4
NETTY_NATIVE_VERSION=2.0.7.Final
NETTY_NATIVE_CLASSIFIER=non-fedora-linux-x86_64

rm -rf elasticsearch-oss-$ES_VERSION
wget http://artifacts.opendistro.amazonaws.com.s3.amazonaws.com/downloads/elasticsearch/elasticsearch-oss-$ES_VERSION.zip
unzip elasticsearch-oss-$ES_VERSION.tar.gz
rm -rf elasticsearch-oss-$ES_VERSION.zip
#wget -O netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar https://search.maven.org/remotecontent?filepath=io/netty/netty-tcnative/$NETTY_NATIVE_VERSION/netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar
mvn clean package -DskipTests
PLUGIN_FILE=($DIR/target/releases/elasticsearch-security-ssl*)
URL=file://$PLUGIN_FILE
echo $URL
elasticsearch-$ES_VERSION/bin/elasticsearch-plugin install -b $URL
RET=$?

if [ $RET -eq 0 ]; then
    echo Installation ok
else
    echo Installation failed
    exit -1
fi


echo "opendistro_security.ssl.transport.enabled: true" > elasticsearch-$ES_VERSION/config/elasticsearch.yml
echo "opendistro_security.ssl.transport.keystore_filepath: node-0-keystore.jks" >> elasticsearch-$ES_VERSION/config/elasticsearch.yml
echo "opendistro_security.ssl.transport.truststore_filepath: truststore.jks" >> elasticsearch-$ES_VERSION/config/elasticsearch.yml
echo "opendistro_security.ssl.transport.enforce_hostname_verification: false" >> elasticsearch-$ES_VERSION/config/elasticsearch.yml

echo "opendistro_security.ssl.http.enabled: true" >> elasticsearch-$ES_VERSION/config/elasticsearch.yml
echo "opendistro_security.ssl.http.keystore_filepath: node-0-keystore.jks" >> elasticsearch-$ES_VERSION/config/elasticsearch.yml
echo "opendistro_security.ssl.http.truststore_filepath: truststore.jks" >> elasticsearch-$ES_VERSION/config/elasticsearch.yml
echo "xpack.security.enabled: false" >> elasticsearch-$ES_VERSION/config/elasticsearch.yml


cp src/test/resources/*.jks elasticsearch-$ES_VERSION/config/

#cp netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar elasticsearch-$ES_VERSION/plugins/elasticsearch-security-ssl/
rm -f netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar
elasticsearch-$ES_VERSION/bin/elasticsearch &

while ! nc -z 127.0.0.1 9200; do
  sleep 0.1 # wait for 1/10 of the second before check again
done

RES="$(curl -Ss --insecure -XGET 'https://127.0.0.1:9200/_opendistro/_security/sslinfo' -H'Content-Type: application/json' | grep ssl_openssl_available)"

if [ -z "$RES" ]; then
  echo "failed"
  exit -1
else
  echo "$RES"
  echo ok
fi

killall java