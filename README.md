# Search Guard SSL for Elasticsearch 2
Elasticsearch SSL for free.

Search Guard SSL is a free and open source plugin for Elasticsearch which provides SSL for Elasticsearch. 
It does not provide authentication and authorization. For that pls refer to [Search Guard](https://github.com/floragunncom/search-guard).

![Logo](https://raw.githubusercontent.com/floragunncom/sg-assets/master/logo/sg_logo_small.jpg) 

##Support
[See wiki](https://github.com/floragunncom/search-guard-ssl/wiki/Support)

##Features
* Node-to-node encryption through SSL/TLS (Transport layer)
* Secure REST layer through HTTPS (SSL/TLS)
* Supports JDK SSL and Open SSL
* Only external dependency is Netty 4 (and Tomcat Native if Open SSL is used)
* Works with Kibana 4, logstash and beats

##Pre-Installation
###Prerequisites:
* Java 7 or 8 (Oracle Java 8 recommended)
* Elasticsearch 2
* Optional: Tomcat Native and Open SSL, see [wiki](https://github.com/floragunncom/search-guard-ssl/wiki/Open-SSL-setup)

###Check Release Integrity
[See wiki](https://github.com/floragunncom/search-guard-ssl/wiki/Check-Release-Integrity)

##Installation
Install it like [any other Elasticsearch plugin](https://www.elastic.co/guide/en/elasticsearch/plugins/2.2/plugin-management.html)

* ``bin/plugin install com.floragunn/search-guard-ssl/<version>`` OR
* ``sudo bin/plugin install com.floragunn/search-guard-ssl/<version>``

``<version> is for example 2.3.1.8 (NOT v2.3.1.8)``

Accept the following warning with y (since ES >= 2.2)

	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@     WARNING: plugin requires additional permissions     @
	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	* java.lang.RuntimePermission accessClassInPackage.sun.misc
	* java.lang.RuntimePermission getClassLoader
	* java.lang.RuntimePermission loadLibrary.*
	* java.lang.reflect.ReflectPermission suppressAccessChecks
	* java.security.SecurityPermission getProperty.ssl.KeyManagerFactory.algorithm
	See http://docs.oracle.com/javase/8/docs/technotes/guides/security/permissions.html
	for descriptions of what these permissions allow and the associated risks.

To find the latest plugin version which is compatible with your Elasticsearch version pls refer to the [wiki](https://github.com/floragunncom/search-guard-ssl/wiki/Check-Release-Integrity).

##Configuration

Search Guard SSL configuration is done in elasticsearch.yml. Please refer to [searchguard-ssl-config-template.yml](searchguard-ssl-config-template.yml) to see the configuration options and their defaults.

Check your configuration by visiting [https://localhost:9200/_searchguard/sslinfo?pretty](https://localhost:9200/_searchguard/sslinfo?pretty) if you have enabled HTTPS or [http://localhost:9200/_searchguard/sslinfo?pretty](http://localhost:9200/_searchguard/sslinfo?pretty) if HTTPS is not enabled.

For details refer to the [wiki](https://github.com/floragunncom/search-guard-ssl/wiki).
If you are running Elasticsearch 2.0.x or 2.1.x you to [disable your security manager](https://github.com/floragunncom/search-guard-ssl/wiki/Disable-security-manager).

###Logging
Configured in elasticsearch's logging.yml. Nothing special. To enable debug just add

``logger.com.floragunn.searchguard.ssl: DEBUG``

###SSL Certificates
* Refer to [wiki](https://github.com/floragunncom/search-guard-ssl/wiki/Generate-Keystores) and [example-pki-scripts](example-pki-scripts) how to generate the certificates. It's strongly recommended to use a root certificate.

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
