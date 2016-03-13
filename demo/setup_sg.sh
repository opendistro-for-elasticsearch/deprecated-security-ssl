SG_VERSION=2.2.0.6
ES_CONF_DIR=/etc/elasticsearch
ES_BIN_DIR=/usr/share/elasticsearch/bin
ES_PLUGIN_DIR=/usr/share/elasticsearch/plugins

if [ ! -f /vagrant/example-pki-scripts/truststore.jks ]
then
    cd /vagrant/example-pki-scripts
    echo "Generating SSL certificates"
    ./example.sh > /dev/null 2>&1
fi


cd /tmp

NETTY_NATIVE_VERSION=1.1.33.Fork12
NETTY_NATIVE_CLASSIFIER=linux-x86_64
wget -O netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar https://search.maven.org/remotecontent?filepath=io/netty/netty-tcnative/$NETTY_NATIVE_VERSION/netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar > /dev/null 2>&1

echo "Install Search Guard SSL Plugin"
sudo $ES_BIN_DIR/plugin install com.floragunn/search-guard-ssl/$SG_VERSION 2>&1
echo "Install netty-tcnative for native Openssl support"
cp netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar $ES_PLUGIN_DIR/search-guard-ssl/

echo "searchguard.ssl.transport.enabled: true" > $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.transport.keystore_filepath: $SSLNAME" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.transport.truststore_filepath: truststore.jks" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.transport.enforce_hostname_verification: false" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.http.enabled: true" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.http.keystore_filepath: $SSLNAME" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.http.truststore_filepath: truststore.jks" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.http.enable_openssl_if_available: $OPENSSL" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.transport.enable_openssl_if_available: $OPENSSL" >> $ES_CONF_DIR/elasticsearch.yml
echo "network.host: _eth1_" >> $ES_CONF_DIR/elasticsearch.yml
echo "discovery.zen.ping.unicast.hosts: 10.0.3.113,10.0.3.112,10.0.3.111" >> $ES_CONF_DIR/elasticsearch.yml
echo "discovery.zen.ping.multicast.enabled: false" >> $ES_CONF_DIR/elasticsearch.yml

cp /vagrant/example-pki-scripts/$SSLNAME $ES_CONF_DIR/
cp /vagrant/example-pki-scripts/truststore.jks $ES_CONF_DIR/
