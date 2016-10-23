#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"


###Some convenience functions

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
    sudo ./lampi -rmd "$site1" >/dev/null 2>&1 && prnt "\tRemoved site: $site1"
    sudo ./lampi -rmd "$site2" >/dev/null 2>&1 && prnt "\tRemoved site: $site2"
    exit $1
}

trap 'Exit 1 2>/dev/null' SIGINT
#trap Exit INT TERM EXIT



doc_root1="$(mktemp -d)"
doc_root2="$(mktemp -d)"
site1=letsacme-host1.local
site2=letsacme-host2.local
acme_dir=$doc_root1/acme-challenge


prnt "\nCreating test sites..."
sudo ./lampi -n "$site1" -dr "$doc_root1" >/dev/null && prnt "\tCreated site: $site1"
sudo ./lampi -n "$site2" -dr "$doc_root2" >/dev/null && prnt "\tCreated site: $site2"

#Test the sites
prnt '\tTesting sites..'
mkdir -p "$doc_root1"/.well-known/acme-challenge
mkdir -p "$doc_root2"/.well-known/acme-challenge

site_test(){
    # $1: burl, $2:docroot
    somefile="$(tr -cd 0-9 </dev/urandom | head -c 65)"
    echo working > "$2/.well-known/acme-challenge/$somefile"
    if curl "$1/.well-known/acme-challenge/$somefile" >/dev/null 2>&1;then
        prnt "\t\tPassed: $1"
    else
        prnt "\t\tFailed: $1"
        Exit 1
    fi
}

site_test "http://$site1" "$doc_root1"
site_test "http://$site2" "$doc_root2"


prnt "\nngrok ..."

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

t1=$(date +%s)
max_t=7 #limit max try in seconds
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
    t2=$(date +%s)
    time="$(expr $t2 - $t1)"
    if [ $time -ge $max_t ]; then
        t1=$(date +%s)
        prnt "\tngork froze. Restarting ..."
        kill $pid >/dev/null 2>&1 && prnt "\tKilled pid: $pid"
        nohup ./ngrok start -config "$nconf_f" $site1 $site2 >/dev/null 2>&1 &
        pid=$!
        prnt "\tngrok restarted (pid: $pid)"
    fi
done

if [ "$dom1" = "$dom2" ]; then
    err '\tE: Both domain can not be same. abort'
    Exit 1 2>/dev/null
fi

prnt "\tSite1: $public_url1"
prnt "\tSite2: $public_url2"
prnt "\tTesting sites ..."

#tphp='<?php phpinfo(); ?>'

#ls -la "$doc_root1" "$doc_root2"

site_test "$public_url1" "$doc_root1"
site_test "$public_url2" "$doc_root2"

#ls -la "$doc_root1" "$doc_root2"

#sleep 30

prnt '\nPreparing ...'
if [ -f account.key ]; then
    prnt '\tUsing existing account.key'
else
    openssl genrsa 4096 > account.key && prnt '\tCreated account.key'
fi
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
"Test":"True"
}' && prnt '\tConfiguration JSON prepared'
#echo "$conf_json" > config.json && prnt '\tCreated config.json file'

prnt '\tRunning letsacme: python ../letsacme.py --config-json $conf_json'

t="$(mktemp)"
{ python ../letsacme.py --config-json "$conf_json" 2>&1; echo $? >"$t"; } | sed -e 's/.*/\t\t&/'
es=$(cat $t)
rm "$t"
if [ $es -eq 0 ]; then
    prnt '\n\t*** success on test 1 ***'
else
    err '\tE: Failed to get the certs'
    #sleep 30
    Exit 1 2>/dev/null
fi

prnt "
*******************************************************
*** Test 2: With --acme-dir and without --config-json
*******************************************************
"

red_code="
RewriteEngine On
RewriteBase /
RewriteRule ^.well-known/acme-challenge/(.*)$ http://$dom1/acme-challenge/\$1 [L,R=302]
"
echo "$red_code" > "$doc_root1"/.htaccess && prnt "\tRedirect for $site1 is set"
echo "$red_code" > "$doc_root2"/.htaccess && prnt "\tRedirect for $site2 is set"

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
