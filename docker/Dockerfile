FROM phusion/baseimage
#:<VERSION>

# docker-compose down && docker-compose build && docker-compose up

# TODO
# Wildcard Certs

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

########## start Oracle 8 Java + Python3
RUN apt-get -yqq update > /dev/null 2>&1
RUN echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections > /dev/null 2>&1
RUN apt-get -yqq install python3 python3-pip software-properties-common > /dev/null 2>&1
RUN add-apt-repository -y ppa:webupd8team/java > /dev/null 2>&1
RUN apt-get -yqq update > /dev/null 2>&1
RUN apt-get -yqq install oracle-java8-installer oracle-java8-unlimited-jce-policy > /dev/null 2>&1
RUN java -version
RUN python3 -V
RUN pip3 -V
########## end Oracle 8 Java + Python3

RUN apt-get -yqq install libssl-dev autoconf libtool build-essential libffi6 libffi-dev git curl wget openssl libapr1 iputils-ping dnsutils host netcat telnet > /dev/null 2>&1
#RUN pip3 install --upgrade urllib3[secure]  > /dev/null 2>&1
RUN pip3 install elasticsearch-curator==3.5.1
RUN pip3 install elasticsearch requests
RUN pip3 install cryptography
RUN pip3 install pyopenssl ndg-httpsclient pyasn1

###### ES
# grab gosu for easy step-down from root
ENV GOSU_VERSION 1.7
RUN set -x \
	&& wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$(dpkg --print-architecture)" > /dev/null 2>&1 \
	&& wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$(dpkg --print-architecture).asc" > /dev/null 2>&1 \
	&& export GNUPGHOME="$(mktemp -d)" \
	&& gpg --keyserver ha.pool.sks-keyservers.net --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 > /dev/null 2>&1 \
	&& gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu > /dev/null 2>&1 \
	&& rm -r "$GNUPGHOME" /usr/local/bin/gosu.asc \
	&& chmod +x /usr/local/bin/gosu \
	&& gosu nobody true

# https://www.elastic.co/guide/en/elasticsearch/reference/current/setup-repositories.html
# https://packages.elasticsearch.org/GPG-KEY-elasticsearch
RUN apt-key adv --keyserver ha.pool.sks-keyservers.net --recv-keys 46095ACC8548582C1A2699A9D27D666CD88E42B4 > /dev/null 2>&1

ENV ELASTICSEARCH_VERSION 2.3.5
ENV ELASTICSEARCH_REPO_BASE http://packages.elasticsearch.org/elasticsearch/2.x/debian

RUN echo "deb $ELASTICSEARCH_REPO_BASE stable main" > /etc/apt/sources.list.d/elasticsearch.list

RUN set -x \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends elasticsearch=$ELASTICSEARCH_VERSION \
	&& rm -rf /var/lib/apt/lists/* > /dev/null 2>&1

ENV PATH /usr/share/elasticsearch/bin:$PATH

WORKDIR /usr/share/elasticsearch

RUN set -ex \
	&& for path in \
		./data \
		./logs \
		./config \
		./config/scripts \
	; do \
		mkdir -p "$path"; \
		chown -R elasticsearch:elasticsearch "$path"; \
	done

VOLUME /usr/share/elasticsearch/data

EXPOSE 9200 9300

ENV ES_VERSION 2.3.5
ENV SG_VERSION 2.3.5.15
ENV NETTY_NATIVE_VERSION 1.1.33.Fork17
ENV NETTY_NATIVE_CLASSIFIER linux-x86_64

ENV ES_CONF_DIR /usr/share/elasticsearch/config
ENV ES_BIN_DIR /usr/share/elasticsearch/bin
ENV ES_PLUGIN_DIR /usr/share/elasticsearch/plugins

ENV ORG_NAME "Example DSG Inc. 1.0"

RUN wget -O netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar https://search.maven.org/remotecontent?filepath=io/netty/netty-tcnative/$NETTY_NATIVE_VERSION/netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar > /dev/null 2>&1

RUN $ES_BIN_DIR/plugin remove search-guard-ssl 2>&1
RUN $ES_BIN_DIR/plugin install com.floragunn/search-guard-ssl/$SG_VERSION 2>&1
RUN cp netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar $ES_PLUGIN_DIR/search-guard-ssl/

ARG SG_HOST

COPY ssl-root-ca/ /search-guard-ssl/example-pki-scripts/
RUN cd /search-guard-ssl/example-pki-scripts && ./gen_node_cert.sh "$ORG_NAME" "CN=$SG_HOST,OU=SSL,O=Test,L=Test,C=DE" "$SG_HOST" changeit "ca pass" > /dev/null 2>&1
RUN cd /search-guard-ssl/example-pki-scripts && ./gen_client_node_cert.sh "$ORG_NAME" "CN=spock,OU=client,O=client,L=Test,C=DE" changeit "ca pass" > /dev/null 2>&1
RUN cd /search-guard-ssl/example-pki-scripts && ./gen_client_node_cert.sh "$ORG_NAME" "CN=kirk,OU=client,O=client,L=Test,C=DE" changeit "ca pass" > /dev/null 2>&1

RUN cp /search-guard-ssl/example-pki-scripts/*.jks $ES_CONF_DIR/
RUN cp /search-guard-ssl/example-pki-scripts/*.pem $ES_CONF_DIR/
RUN cp /search-guard-ssl/example-pki-scripts/ca/*.pem $ES_CONF_DIR/

RUN chown elasticsearch:elasticsearch $ES_CONF_DIR/*

RUN mkdir /etc/service/dns
ADD dns.sh /etc/service/dns/run
RUN chmod +x /etc/service/dns/run

RUN mkdir /etc/service/clients
ADD clients.sh /etc/service/clients/run
RUN chmod +x /etc/service/clients/run

RUN mkdir /etc/service/elasticsearch
ADD elasticsearch.sh /etc/service/elasticsearch/run
RUN chmod +x /etc/service/elasticsearch/run

COPY config ./config
ADD esclient.py /esclient.py

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#RUN rm -f /etc/service/sshd/down
#RUN /usr/sbin/enable_insecure_key