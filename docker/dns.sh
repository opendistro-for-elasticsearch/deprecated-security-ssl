#!/bin/sh
# ugly hack for https://github.com/docker/docker/issues/26298
while :
do
    #cat /etc/resolv.conf
    #cat /etc/hosts
	echo "nameserver 8.8.8.8" > /etc/resolv.conf
	echo "127.0.0.1 localhost" > /etc/hosts
	echo "172.16.0.1 sgssl-0.example.com" >> /etc/hosts
	echo "172.16.0.2 sgssl-1.example.com" >> /etc/hosts
	echo "172.16.0.3 sgssl-2.example.com" >> /etc/hosts
	sleep 1
done