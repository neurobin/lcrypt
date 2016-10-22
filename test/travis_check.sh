#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"

prnt(){
    printf "$*\n" >>/dev/stdout
}
err() {
    printf "$*\n" >>/dev/stderr
}

Exit(){
    prnt '\nCleaning'
    if [ "$2" != '-p' ]; then
        kill $pid >/dev/null 2>&1 && prnt "\tKilled pid: $pid"
    fi
#    mv -f "$doc_root1"/.htaccess.bak "$doc_root1"/.htaccess >/dev/null 2>&1
#    mv -f "$doc_root2"/.htaccess.bak "$doc_root2"/.htaccess >/dev/null 2>&1
#    sudo ./lampi -rm "$site1" >/dev/null 2>&1 && prnt "\tRemoved site: $site1"
#    sudo ./lampi -rm "$site2" >/dev/null 2>&1 && prnt "\tRemoved site: $site2"
    exit $1
}

trap 'Exit 1 2>/dev/null' SIGINT

doc_root1=/var/www/html
doc_root2=/var/www/html
site1=letsacme-host1.local
site2=letsacme-host2.local
acme_dir=/var/www/acme-challenge


prnt "\nCreating test sites..."
#sudo ./lampi -n "$site1" -dr "$doc_root1" -nsr >/dev/null && prnt "\tCreated site: $site1"
#sudo ./lampi -n "$site2" -dr "$doc_root2" -nsr >/dev/null && prnt "\tCreated site: $site2"
#sudo sed -i .bak -e 's/ServerName.*//' "/etc/apache2/sites-available/$site1.conf"
#sudo sed -i .bak -e 's/ServerName.*//' "/etc/apache2/sites-available/$site2.conf"
#a2ensite $site1
#a2ensite $site2
#sudo service apache2 restart >/dev/null && prnt "\tReloaded apache2"


#create backup .htaccess file
#mv -f "$doc_root1"/.htaccess "$doc_root1"/.htaccess.bak >/dev/null 2>&1
#mv -f "$doc_root2"/.htaccess "$doc_root2"/.htaccess.bak >/dev/null 2>&1



sudo mkdir -p "$doc_root1"
sudo mkdir -p "$doc_root2"
sudo mkdir -p "$acme_dir"
sudo chown -R $USER:$USER "$doc_root2" "$doc_root1" "$acme_dir"

#get_conf(){
#    #$1: dr
#    prnt "<VirtualHost *:80>
##            ServerName $2
##            ServerAlias $2
#            ServerAdmin webmaster@$2
#            DocumentRoot $1
#            <Directory $1>
#                    Options Indexes FollowSymLinks MultiViews
#                    AllowOverride All
#                    Require all granted
#            </Directory>
#        </VirtualHost>"
#}

#get_conf "$doc_root1" "$site1" | sudo tee /etc/apache2/sites-available/"$site1".conf > /dev/null
##cat /etc/apache2/sites-available/"$site1".conf

#get_conf "$doc_root2" "$site2" | sudo tee /etc/apache2/sites-available/"$site2".conf > /dev/null
##cat /etc/apache2/sites-available/"$site2".conf

manage_host(){
    #$1:dom
    if ! grep -s -e "^127.0.0.1[[:blank:]]*$1[[:blank:]]*$" /etc/hosts >/dev/null 2>&1; then
        sudo sed -i.bak -e "1 a 127.0.0.1\t$1" /etc/hosts &&
        printf "\tAdded $1 to /etc/hosts\n" ||
        printf "\tE: Failed to add $1 to /etc/hosts\n"
    fi
}
#echo "" |sudo tee -a /etc/hosts >/dev/null
#sudo sed -i.bak 's/127\.0\.0\.1.*/127.0.0.1 localhost/' /etc/hosts
manage_host "$site1"
manage_host "$site2"
#echo " $site1 $site2" |sudo tee -a /etc/hosts
#cat /etc/hosts

#sudo a2dissite 000-default
#sudo a2ensite "$site1" >/dev/null 2>&1 && prnt "\tCreated site: $site1"
#sudo a2ensite "$site2" >/dev/null 2>&1 && prnt "\tCreated site: $site2"
#sudo a2enmod rewrite >/dev/null 2>&1

prnt "\nngrok ..."

#download ngrok
#wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip -O ngrok-stable-linux-amd64.zip
#unzip ngrok-stable-linux-amd64.zip
nweb=127.0.0.1:4040
nconf="tunnels:
  $site1:
    proto: http
    host_header: rewrite
    addr: $site1:80
    web_addr: $nweb
  $site2:
    proto: http
    host_header: rewrite
    addr: $site2:80
    web_addr: $nweb"
nconf_f=ngrok.yml
echo "$nconf" > "$nconf_f" && prnt '\tCreated ngrok config file'

nohup ./ngrok start -config "$nconf_f" $site1 $site2 >/dev/null 2>&1 &
pid=$!
prnt "\tRunning ngrok in the background (pid: $pid)"

while true; do
    tunnel_info_json="$(curl -s http://$nweb/api/tunnels)"
    #echo $tunnel_info_json
    public_url1="$(echo "$tunnel_info_json" | jq -r '.tunnels[0].public_url' | grep 'http://')"
    dom1="$(echo "$public_url1" |sed -n -e 's#.*//\([^/]*\)/*.*#\1#p')"
    public_url2="$(echo "$tunnel_info_json" | jq -r '.tunnels[2].public_url' | grep 'http://')"
    dom2="$(echo "$public_url2" |sed -n -e 's#.*//\([^/]*\)/*.*#\1#p')"
    if [ -n "$dom1" ] && [ -n "$dom2" ]; then
        break
    fi
done

if [ "$dom1" = "$dom2" ]; then
    err '\tE: Both domain can not be same. abort'
    Exit 1 2>/dev/null
fi

prnt "\tSite1: $public_url1"
prnt "\tSite2: $public_url2"


#tphp='<?php phpinfo(); ?>'

#echo working1 > "$doc_root1"/somefile
#echo working2 > "$doc_root2"/somefile

#ls -la "$doc_root1" "$doc_root2"

#prnt "URL1: $public_url1/somefile"
#prnt "URL2: $public_url2/somefile"

#curl "$public_url1/somefile"
#curl "$public_url2/somefile"
#curl "$public_url1"

prnt '\nPreparing ...'

#openssl genrsa 4096 > account.key && prnt '\tCreated account.key'
printf "$dom1\n$dom2\n" > dom.list && prnt '\tCreated dom.list file'
./gencsr >/dev/null && prnt '\tCreated CSR'

prnt '
*********************************************************
*** Test 1: With --config-json and using document root
*********************************************************
'

conf_json='{
"'$dom1'":
    {
        "DocumentRoot": "'$doc_root1'"
    },
"'$dom2'":
    {
        "DocumentRoot": "'$doc_root2'"
    },
"DocumentRoot": "'$doc_root2'",
"AccountKey":"account.key",
"CSR": "dom.csr",
"CertFile":"dom.crt",
"ChainFile":"chain.crt",
"CA":"",
"NoChain":"False",
"NoCert":"False",
"Test":"True",
"Force":"False"
}'
echo "$conf_json" > config.json && prnt '\tCreated config.json file'

prnt "\tRunning letsacme: python ../letsacme.py --config-json config.json"
#echo "" > "$doc_root1"/.htaccess
#echo "" > "$doc_root2"/.htaccess
#sleep 30
t="$(mktemp)"
{ python ../letsacme.py --config-json config.json 2>&1; echo $? >"$t"; } | sed -e 's/.*/\t\t&/'
es=$(cat $t)
rm "$t"
if [ $es -eq 0 ]; then
    prnt '\n\t*** success on test 1 ***'
else
    err '\tE: Failed to get the certs'
    Exit 1 2>/dev/null
fi

prnt "
*******************************************************
*** Test 2: With --acme-dir and without --config-json
*******************************************************
"

#red_code="
#RewriteEngine On
#RewriteBase /
#RewriteRule ^.well-known/acme-challenge/(.*)$ http://$dom1/acme-challenge/\$1 [L,R=302]
#"
#echo "$red_code" > "$doc_root1"/.htaccess && prnt "\tRedirect for $site1 is set"
#echo "$red_code" > "$doc_root2"/.htaccess && prnt "\tRedirect for $site2 is set"

alias="Alias /.well-known/acme-challenge $acme_dir\n<Directory $acme_dir>\nRequire all granted\n</Directory>"

sudo sed -i.bak -e "s#<VirtualHost[^>]*>#&\n$alias#" /etc/apache2/sites-available/000-default.conf
#cat /etc/apache2/sites-available/000-default.conf
sudo a2enmod alias >/dev/null 2>&1
#sudo a2enmod actions
sudo service apache2 restart >/dev/null 2>&1 && prnt '\tReloaded apache2' || err '\tE: Failed to reload apache2'

prnt "\tRunning letsacme:
\tpython ../letsacme.py --test\\\\\n\t  --account-key account.key\\\\\n\t  --csr dom.csr\\\\\n\t  --acme-dir $acme_dir\\\\\n\t  --chain-file chain.crt\\\\\n\t  --cert-file dom.crt"
t="$(mktemp)"
{ python ../letsacme.py --test --account-key account.key --csr dom.csr --acme-dir "$acme_dir" --chain-file chain.crt --cert-file dom.crt 2>&1; echo $? >"$t"; } | sed -e 's/.*/\t\t&/'
es=$(cat "$t")
rm $t
if [ $es -eq 0 ]; then
    prnt '\n\t*** success on test 2 ***'
else
    err '\tE: Failed to get the certs'
    Exit 1 2>/dev/null
fi

############## Final cleaning ###############
Exit 0 2>/dev/null
#############################################
