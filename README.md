# Search Guard SSL for ES 2.1
Elasticsearch SSL for free.

Search Guard SSL is a free and open source plugin for Elasticsearch which provides SSL for Elasticsearch. 
It does not provide authentication and authorization. For that pls refer to [Search Guard](https://github.com/floragunncom/search-guard).

![Logo](https://raw.githubusercontent.com/floragunncom/sg-assets/master/logo/sg_logo_small.jpg) 

[![Build Status](https://travis-ci.org/floragunncom/search-guard-ssl.svg?branch=master)](https://travis-ci.org/floragunncom/search-guard-ssl) [![Coverage Status](https://coveralls.io/repos/floragunncom/search-guard-ssl/badge.svg?branch=master)](https://coveralls.io/r/floragunncom/search-guard-ssl?branch=master)

##Support
* Community support available via [google groups](https://groups.google.com/forum/#!forum/search-guard)
* Commercial support through [floragunn UG](http://floragunn.com) available Februar 2016

##Features
* Node-to-node encryption through SSL/TLS (Transport layer)
* Secure REST layer through HTTPS (SSL/TLS)
* Supports JDK SSL and Open SSL
* Only external dependency is Netty 4 (and Tomcat Native if Open SSL is used)
* Works with Kibana 4, logstash and beats

##Pre-Installation
###Check Release Integrity

You **must** verify the integrity of the [downloaded file](https://oss.sonatype.org/content/repositories/releases/com/floragunn/search-guard-ssl/2.1.0.1/). We provide PGP signatures for every release file. This signature should be matched against the KEYS file. We also provide MD5 and SHA-1 checksums for every release file. After you download the file, you should calculate a checksum for your download, and make sure it is the same as ours. [Here](http://www.openoffice.org/download/checksums.html) and [here](https://www.apache.org/info/verification.html) are some tips how to verify the pgp signatures.

##Installation
Install it like any other Elasticsearch plugin

``sudo bin/plugin install com.floragunn/search-guard-ssl/2.1.0.3``

Prerequisites:

* Java 7 or 8 (recommended)
* Elasticsearch 2.1.0
* Optional: Tomcat Native and Open SSL, see [wiki](https://github.com/floragunncom/search-guard-ssl/wiki)

Build it yourself:

* Install maven 3.1+
* ``git clone https://github.com/floragunncom/search-guard-ssl.git``
* ``cd search-guard-ssl``
* execute ``mvn package -DskipTests`` 


##Configuration

Search Guard SSL configuration is done in elasticsearch.yml. Please refer to [searchguard-ssl-config-template.yml](searchguard-ssl-config-template.yml) to see the configuration options and their defaults.

Note:

* ``security.manager.enabled`` - Must currently be set to ``false``. This will likely change with Elasticsearch 2.2, see [PR 14108](https://github.com/elastic/elasticsearch/pull/14108)

Check your configuration by visiting [https://localhost:9200/_searchguard/sslinfo?pretty](https://localhost:9200/_searchguard/sslinfo?pretty) if you have enabled HTTPS or [http://localhost:9200/_searchguard/sslinfo?pretty](http://localhost:9200/_searchguard/sslinfo?pretty) if HTTPS is not enabled.

For details refer to the [wiki](https://github.com/floragunncom/search-guard-ssl/wiki).



###Logging
Configured in elasticsearch's logging.yml. Nothing special. To enable debug just add

``logger.com.floragunn.searchguard.ssl: DEBUG``


###SSL Certificates
* Refer to [example-pki-scripts](example-pki-scripts) how to generate the certificates. It's strongly recommended to use a root certificate.
* See also [https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores](https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores)
* or [https://tomcat.apache.org/tomcat-8.0-doc/ssl-howto.html](https://tomcat.apache.org/tomcat-8.0-doc/ssl-howto.html)

###Update and Upgrade
TBD

###License
Copyright 2015 floragunn UG (haftungsbeschränkt)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   ``http://www.apache.org/licenses/LICENSE-2.0``

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
