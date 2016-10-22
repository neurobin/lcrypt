#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"

#sudo add-apt-repository -y ppa:ondrej/apache2
#sudo add-apt-repository -y ppa:ondrej/php5
sudo apt-get update
sudo apt-get install -qq apache2
sudo apt-get install -qq jq nohup

#download ngrok
wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip -O ngrok-stable-linux-amd64.zip
unzip ngrok-stable-linux-amd64.zip
