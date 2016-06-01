# Search Guard SSL for Elasticsearch 2
Elasticsearch SSL for free.

Search Guard SSL is a free and open source plugin for Elasticsearch which provides SSL for Elasticsearch. 
It does not provide authentication and authorization. For that pls refer to [Search Guard](https://github.com/floragunncom/search-guard).

![Logo](https://raw.githubusercontent.com/floragunncom/sg-assets/master/logo/sg_logo_small.jpg) 

##Features
* Node-to-node encryption through SSL/TLS (Transport layer)
* Secure REST layer through HTTPS (SSL/TLS)
* Supports JDK SSL and Open SSL
* Only external dependency is Netty 4 (and Tomcat Native if Open SSL is used)
* Works with Kibana 4, logstash and beats

##Documentation
Documentation is provided in a separate repository in markdown format.

[Search Guard SSL Documentation](https://github.com/floragunncom/search-guard-ssl-docs)

##Support
[See wiki](https://github.com/floragunncom/search-guard-ssl/wiki/Support)

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
