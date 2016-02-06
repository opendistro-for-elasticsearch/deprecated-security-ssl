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
echo "Install guest additions"
sudo apt-get -yqq install virtualbox-guest-additions-iso > /dev/null 2>&1
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

while ! nc -z localhost 9200; do   
  sleep 0.1 # wait for 1/10 of the second before check again
done

curl -Ss --insecure https://localhost:9200/_cluster/health?pretty
curl -Ss --insecure https://127.0.0.1:9200/_searchguard/sslinfo?pretty

SCRIPT


# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu/trusty64"
  config.vm.network :forwarded_port, guest: 9200, host: 9200
  #config.vm.network :forwarded_port, guest: 88, host: 8888, protocol: 'udp'
  config.vm.network :forwarded_port, guest: 9300, host: 9300

  config.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--cpus", "2", "--memory", "2048"]
      #vb.customize ["modifyvm", :id, "--cpus", "1", "--memory", "1024"]
  end
  config.vm.provision "shell", inline: $script
end
