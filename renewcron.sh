#!/bin/sh
while true;do
    if python /path/to/letsacme.py --account-key /path/to/account.key \
        --csr /path/to/domain.csr \
        --config-json /path/to/config1.json \
        --cert-file /path/to/signed.crt \
        --chain-file /path/to/chain.crt \
        > /path/to/fullchain.crt \
        2>> /path/to/letsacme.log
    then
        # echo "Successfully renewed certificate"
        service apache2 restart
        break
    else
        sleep `tr -cd 0-9 </dev/urandom | head -c 4`
        # sleep for max 9999 seconds, then try again
        # echo "Retry triggered"
    fi
done

