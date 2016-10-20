#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"

#download gencsr (CSR generator)
wget https://raw.githubusercontent.com/neurobin/gencsr/release/gencsr -O gencsr
wget https://raw.githubusercontent.com/neurobin/gencsr/release/gencsr.conf -O gencsr.conf

#download ngrok
wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip -O ngrok-stable-linux-amd64.zip
unzip ngrok-stable-linux-amd64.zip

#download lampi (lamp installer for ubuntu)
wget https://raw.githubusercontent.com/neurobin/lampi/release/lampi -O lampi
chmod +x lampi

#install jq
sudo apt-get install jq


#install LAMP stack
if [ "$1" != '-d' ]; then
    sudo ./lampi -i
fi
