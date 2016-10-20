#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"


clean_me(){
    echo '
    **** Cleaning ... ****
    '
    echo 'Stopping ngrok ...'
    kill $pid

    echo 'Removing temporary sites ...'
    sudo ./lampi -rm "$dom1" || true
    sudo ./lampi -rm "$dom2" || true
}

trap clean_me SIGINT

./ngrok start -config ./ngrok.yml dom1 dom2 >/dev/null &
export pid=$!
echo "Preparing ngrok in the background (pid: $pid)
Please wait ...
"
while true; do
    api_tunnel='http://127.0.0.1:4040/api/tunnels'
    tunnel_info_json="$(curl -s http://127.0.0.1:4040/api/tunnels)"
    public_url1="$(echo "$tunnel_info_json" | jq -r '.tunnels[0].public_url' | grep 'http://')"
    dom1="$(echo "$public_url1" |sed -n -e 's#.*//\([^/]*\)/*.*#\1#p')"
    public_url2="$(echo "$tunnel_info_json" | jq -r '.tunnels[2].public_url' | grep 'http://')"
    dom2="$(echo "$public_url2" |sed -n -e 's#.*//\([^/]*\)/*.*#\1#p')"
    if [ -n "$dom1" ] && [ -n "$dom2" ]; then
        break
    fi
done
if [ "$dom1" = "$dom2" ]; then
    echo 'E: both domain can not be same. abort' >>/dev/stderr
    kill $pid
    exit 1
fi
echo "Our test domains are : $dom1, $dom2"
doc_root1=$HOME/letsacme-host1
doc_root2=$HOME/letsacme-host2
acme_dir=$doc_root1/acme-challenge

echo "Creating test servers at local host..."
sudo ./lampi -n "$dom1" -dr "$doc_root1"
sudo ./lampi -n "$dom2" -dr "$doc_root2"

echo 'Creating account key...'
openssl genrsa 4096 > account.key

echo 'Creating CSR...'
echo "$dom1
$dom2" > dom.list
./gencsr

echo 'Checking Document Root method...'
echo 'Creating config json...'
conf_json='{
"'$dom1'": {
            "DocumentRoot": "'$doc_root1'"
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
echo "$conf_json" |tee config.json

echo "
******* Running letsacme... **********
python ../letsacme.py --config-json config.json
"
echo "" > "$doc_root1"/.htaccess
echo "" > "$doc_root2"/.htaccess
sleep 30
if python ../letsacme.py --config-json config.json; then
    echo '
    *** success on Document Root method ***
    '
else
    echo '
    E: Failed to get the certs
    ' >/dev/stderr
    clean_me
    exit 1
fi

echo "Checking AcmeDir method ... "
echo "Setting up redirect ..."
red_code="
RewriteEngine On
RewriteBase /
RewriteRule ^.well-known/acme-challenge/(.*)$ http://$dom1/acme-challenge/\$1 [L,R=302]
"
echo "$red_code" > "$doc_root1"/.htaccess
echo "$red_code" > "$doc_root2"/.htaccess

echo "Running letsacme ...
python ../letsacme.py --test --account-key account.key --csr dom.csr --acme-dir $acme_dir --chain-file chain.crt --cert-file dom.crt
"
if python ../letsacme.py --test --account-key account.key --csr dom.csr --acme-dir "$acme_dir" --chain-file chain.crt --cert-file dom.crt; then
    echo '
    *** success on Acme Dir method ***
    '
else
    echo '
    E: Failed to get the certs
    ' >/dev/stderr
    clean_me
    exit 1
fi
clean_me
