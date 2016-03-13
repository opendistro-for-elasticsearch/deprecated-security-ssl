#!/bin/sh
#########
# No magic here, we just install java and openssl
#########
$script = <<SCRIPT
export DEBIAN_FRONTEND=noninteractive
echo "Update packages"
sudo killall -9 java > /dev/null 2>&1
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - > /dev/null 2>&1
echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list > /dev/null 2>&1
sudo apt-get -yqq update > /dev/null 2>&1
#echo "Install guest additions"
#sudo apt-get -yqq install virtualbox-guest-additions-iso > /dev/null 2>&1
echo "Prepare Java installation"
echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | sudo /usr/bin/debconf-set-selections > /dev/null 2>&1
sudo apt-get -yqq install curl software-properties-common > /dev/null 2>&1
sudo add-apt-repository -y ppa:webupd8team/java > /dev/null 2>&1
sudo apt-get -yqq update > /dev/null 2>&1
echo "Install Oracle Java 8, libapr1 and openssl"
sudo apt-get -yqq install haveged libapr1 openssl wget git oracle-java8-installer oracle-java8-unlimited-jce-policy > /dev/null 2>&1
#sudo apt-get -yqq install autoconf libtool libssl-dev libkrb5-dev python-dev python-pip haveged openssl wget git oracle-java8-installer oracle-java8-unlimited-jce-policy > /dev/null 2>&1
#sudo apt-get install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" krb5-user > /dev/null 2>&1
# entropy generator
#haveged -w 1024 > /dev/null 2>&1
#########
# Install elasticsearch (from official repo)
# https://www.elastic.co/guide/en/elasticsearch/reference/current/setup-repositories.html
#########
echo "Install Elasticsearch"
sudo apt-get install -yqq elasticsearch=2.2.0 > /dev/null 2>&1

#########
# Setup search Guard SSL
#########
echo "Setup search Guard SSL"
#su -c "/vagrant/demo/setup_sg.sh" vagrant
/vagrant/demo/setup_sg.sh

echo "Start Elasticsearch"
/etc/init.d/elasticsearch restart

IP=$(hostname -I | cut -f2 -d' ')

while ! nc -z $IP 9200; do   
  sleep 0.1 # wait for 1/10 of the second before check again
done

curl -Ss --insecure https://$IP:9200/_cluster/health?pretty
curl -Ss --insecure https://$IP:9200/_searchguard/sslinfo?pretty

SCRIPT
#End inline script

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

   config.vm.provision :hosts do |prov|
        prov.add_host '10.0.3.111', ['es1']
        prov.add_host '10.0.3.112', ['es2']
        prov.add_host '10.0.3.113', ['es3']
   end

   config.vm.define "es1" do |es1|
        es1.vm.box = "ubuntu/trusty64"
        es1.vm.hostname = "es1"
        es1.vm.network "private_network", ip: "10.0.3.111"
        es1.vm.provision "shell", inline: 'echo "export SSLNAME=node-0-keystore.jks" >> ~/.profile'
        es1.vm.provision "shell", inline: 'echo "export OPENSSL=true" >> ~/.profile'
        es1.vm.provision "shell", inline: $script
        es1.vm.provider "virtualbox" do |v|
                     v.memory = 768 
                     v.cpus = 2
             end
   end

   config.vm.define "es2" do |es2|
        es2.vm.box = "ubuntu/trusty64"
        es2.vm.hostname = "es2"
        es2.vm.network "private_network", ip: "10.0.3.112"
        es2.vm.provision "shell", inline: 'echo "export SSLNAME=node-1-keystore.jks" >> ~/.profile'
        es2.vm.provision "shell", inline: 'echo "export OPENSSL=true" >> ~/.profile'
        es2.vm.provision "shell", inline: $script
        es2.vm.provider "virtualbox" do |v|
                     v.memory = 768 
                     v.cpus = 2
             end
   end

   config.vm.define "es3" do |es3|
        es3.vm.box = "ubuntu/trusty64"
        es3.vm.hostname = "es3"
        es3.vm.network "private_network", ip: "10.0.3.113"
        es3.vm.provision "shell", inline: 'echo "export SSLNAME=node-2-keystore.jks" >> ~/.profile'
        es3.vm.provision "shell", inline: 'echo "export OPENSSL=false" >> ~/.profile'
        es3.vm.provision "shell", inline: $script
        es3.vm.provider "virtualbox" do |v|
                     v.memory = 768 
                     v.cpus = 2
             end
   end

end
