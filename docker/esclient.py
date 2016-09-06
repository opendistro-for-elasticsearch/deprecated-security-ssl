from elasticsearch import Elasticsearch, RequestsHttpConnection, Urllib3HttpConnection
import ssl

import urllib3
import urllib3.contrib.pyopenssl

urllib3.contrib.pyopenssl.inject_into_urllib3()

print("--------------- Python URLLIB 3 --------------------------------")

http = urllib3.PoolManager(
ca_certs="/usr/share/elasticsearch/config/chain-ca.pem",
cert_reqs='CERT_REQUIRED',
cert_file='/usr/share/elasticsearch/config/CN=picard,OU=client,O=client,L=Test,C=DE.crtfull.pem',
key_file='/usr/share/elasticsearch/config/CN=picard,OU=client,O=client,L=Test,C=DE.key.pem',
)

r = http.request('GET', 'https://sgssl-0.example.com:9200')
udata=r.data
print(udata)

print("--------------- Python Elasticsearch client --------------------------------")

es = Elasticsearch(
    ['sgssl-0.example.com:9200'],
    connection_class=RequestsHttpConnection,
    use_ssl=True,
    verify_certs=True,
    ca_certs='/usr/share/elasticsearch/config/chain-ca.pem',
    client_cert='/usr/share/elasticsearch/config/CN=picard,OU=client,O=client,L=Test,C=DE.crtfull.pem',
    ssl_version=ssl.PROTOCOL_TLSv1_2,
    ssl_assert_hostname=True,
    client_key='/usr/share/elasticsearch/config/CN=picard,OU=client,O=client,L=Test,C=DE.key.pem'
    )
print(es.info())

print("--------------- Python Raw SSL socket --------------------------------")

import socket
packet=b"GET /_search HTTP/1.1\nHost: sgssl-0.example.com\n\n"
HOST, PORT = 'sgssl-0.example.com', 9200

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
wrappedSocket = ssl.wrap_socket(sock=sock, cert_reqs=ssl.CERT_REQUIRED, keyfile='/usr/share/elasticsearch/config/CN=picard,OU=client,O=client,L=Test,C=DE.key.pem', certfile='/usr/share/elasticsearch/config/CN=picard,OU=client,O=client,L=Test,C=DE.crtfull.pem',  ca_certs='/usr/share/elasticsearch/config/chain-ca.pem', ssl_version=ssl.PROTOCOL_TLSv1_2)

wrappedSocket.connect((HOST, PORT))
wrappedSocket.send(packet)
data=wrappedSocket.recv(4096)
stz=data.decode()
print(stz)
wrappedSocket.close()