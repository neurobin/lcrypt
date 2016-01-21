The **letsacme** script automates the process of getting a signed TLS/SSL certificate from Let's Encrypt using the ACME protocol. It will need to be run on your server and have **access to your private account key**. It gets both the certificate and the chain (CABUNDLE) and prints them on stdout unless specified otherwise.

**PLEASE READ THE SOURCE CODE (~350 LINE)! YOU MUST TRUST IT WITH YOUR PRIVATE KEYS!**

#Dependencies:
1. Python
2. openssl

#How to use:

If you just want to renew an existing certificate, you will only have to do Steps 4~6. 

**For shared servers/hosting:** Get only the certificate (step 1~4) by running the script on your server and then install the certificate with cpanel or equivalent control panels.

## 1: Create a Let's Encrypt account private key (if you haven't already):
You must have a public key registered with Let's Encrypt and use the corresponding private key to sign your requests. Thus you first need to create a key, which **letsacme** will use to register an account for you and sign all the following requests.

If you don't understand what the account is for, then this script likely isn't for you. Please, use the official Let's Encrypt client. Or you can read the [howitworks](https://letsencrypt.org/howitworks/technology/) page under the section: **Certificate Issuance and Revocation** to gain a little insight on how certificate issuance works.

The following command creates a 4096bit RSA (private) key:
```sh
openssl genrsa 4096 > account.key
```

**Or use an existing Let's Encrypt key (privkey.pem from official Let's Encrypt client)**

**Note:** **letsacme** is using the [PEM](https://tools.ietf.org/html/rfc1421) key format.

##2: Create a certificate signing request (CSR) for your domains.

The ACME protocol used by Let's Encrypt requires a CSR to be submitted to it (even for renewal). Once you have the CSR, you can use the same CSR as many times as you want. You can create a CSR from the terminal which will require you to create a domain key first, or you can create it from the control  panel provided  by your hosting provider (for example: cpanel). Whatever method you may use to create the CSR, the script doesn't require the domain key, only the CSR.

**Note:** Domain key is not the private key you previously created.

###An example of creating CSR using openssl:
The following command will create a 4096bit RSA (domain) key:
```sh
openssl genrsa 4096 > domain.key
```
Now to create a CSR for a single domain:
```sh
openssl req -new -sha256 -key domain.key -subj "/CN=example.com" > domain.csr
```
For multi-domain:
```sh
openssl req -new -sha256 \
    -key domain.key \
    -subj "/C=US/ST=CA/O=MY Org/CN=example.com" \
    -reqexts SAN \
    -config <(cat /etc/ssl/openssl.cnf \
        <(printf "[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com,DNS:subdomain.example.com,DNS:www.subdomain.com")) \
    -out domain.csr
```

##3: Prepare the challenge directory/s:
**letsacme** provides two methods to prepare the challenge directory/s to complete the acme challenges. One of them is the same as [acme-tiny](https://github.com/diafygi/acme-tiny) (with `--acme-dir`), the other is quite different and simplifies things for users who doesn't have full access to their servers i.e for shared servers or shared hosting. 

**Whatever method you use, note that the challenge directory needs to be accessible with normal http on port 80.**

Otherwise, you may get an **error message** like this one:
```
Wrote file to /var/www/public_html/.well-known/acme-challenge/rgGoLnQ8VkBOPyXZn-PkPD-A3KH4_2biYVOxbrYRDuQ, but couldn't download http://example.org/.well-known/acme-challenge/rgGoLnQ8VkBOPyXZn-PkPD-A3KH4_2biYVOxbrYRDuQ
```
See section 3.3 on how you can work this around.

###3.1: Using configuration JSON:
**letsacme** uses a JSON file to get the required information it needs to write challenge files on the server. This method is different than the acme-tiny script which this script is based on. Acme-tiny requires you to configure your server for completing the challenge; contrary to that, the intention behind this method is to not do anything at all on the server configuration until we finally get the certificate. Instead of setting up your server, **letsacme** requires you to provide the document root of each domain in a JSON format. It will create the *.well-known/acme-challenge* directory under document root (if not exists already) and put the temporary challenge files there. Instead of document root you can use other directory/s too; but in that case you will need to redirect all requests to http://example.org/.well-known/acme-challenge/.* to the URL of that directory.

An example config file looks like this:

**config.json:**
```json
{
"example.org": {
    "DocumentRoot":"/var/www/public_html"
    },
"subdomain1.example.org": {
    "DocumentRoot":"/var/www/subdomain1"
    },
"subdomain2.example.org": {
    "DocumentRoot":"/var/www/subdomain2"
    },
"subdomain3.example.org": {
    "DocumentRoot":"/var/www/subdomain3"
    },
"subdomain4.example.org": {
    "DocumentRoot":"/var/www/subdomain4"
    },
"subdomain5.example.org": {
    "DocumentRoot":"/var/www/subdomain5"
    }
}
```

###3.2: Using acme-dir as in acme-tiny:
This method is the same as acme-tiny. This is an abundant feature of **letsacme** as the above Config JSON method is enough for all cases. It is provided only to be compatible with acme-tiny, i.e the same method to run the acme-tiny client will work for this script too. But the output is different than the acme-tiny tool (by default). While acme-tiny prints only the cert on stdout, **letsacme** prints both cert and chain (i.e fullchain) on stdout by default. If you provide `--no-chain` then the output will match that of acme-tiny.

acme-dir method requires you to create a challenge directory first:
```sh
#make some challenge folder (modify to suit your needs)
mkdir -p /var/www/challenges/
```
Then you need to configure your server. 

Example for nginx (copied from acme-tiny readme):
```nginx
server {
    listen 80;
    server_name yoursite.com www.yoursite.com;

    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }

    ...the rest of your config
}
```
On apache2  you can set Aliases:
```apache
Alias /.well-known/acme-challenge /var/www/challenges
```
You can't use this method on shared server as most of the shared server won't allow Aliases in AccessFile.

###3.3 What will you do if the challenge directory/document root doesn't allow normal http on port 80:
**The challenge directory must be accessible with normal http on port 80.**

But this may not be possible all the time. So, what will you do?

And also there's another scenario: if it happens that your site is behind a firewall or your WordPress site or site with Laravel or other tools and framework is preventing direct access to that challenge directory, what will you do?

In the above cases most commonly you will be rendered with an error message like this:

>Wrote file to /var/www/public_html/.well-known/acme-challenge/rgGoLnQ8VkBOPyXZn-PkPD-A3KH4_2biYVOxbrYRDuQ, but couldn't download http://example.org/.well-known/acme-challenge/rgGoLnQ8VkBOPyXZn-PkPD-A3KH4_2biYVOxbrYRDuQ

This means what it **exactly means**, it can't access the challenge files on the URL, it is either being redirected in a weird way or blocked.

You can however work this around with an effective but peculiar way:

Create a subdomain (or use an existing one with no additional framework, just plain old http site). Check if the subdomain is accessible (by creating a simple html file inside). Create a directory named `challenge` inside it's document root (don't use `.well-known/acme-challenge` instead of `challenge`, it will create an infinite loop if this new subdomain also contains the following line of redirection code). And then redirect all *.well-know/acme-challenge* requests to all of the domains you want certificate for, to this directory of this new subdomain. A mod_rewrite rule for apache2 would be:
```apache
RewriteRule ^.well-known/acme-challenge/(.*)$ http://challenge.example.org/challenge/$1 [L,R=302]
```
And provide the challenge directory (the `challenge` directory path inside the document root) to **letsacme** as an *acme-dir* (not as document root) with `--acme-dir` option.

Even though it's peculiar and a bit tedious, it is supposed to work with all the situations as long as the subdomain is properly active. So if you want to move to this method instead of all the other methods available, I wouldn't stop you.


##4: Get a signed certificate:
To get a signed certificate, all you need is the private key and the CSR.

If you created the *config.json* file in previous step:
```sh
python letsacme.py --no-chain --account-key ./account.key --csr ./domain.csr --config-json ./config.json > ./signed.crt
```
If you didn't create the config.json file, then pass the json string itself as an argument:
```sh
python letsacme.py --no-chain --account-key ./account.key --csr ./domain.csr --config-json '{"example.com":{"DocumentRoot":"/var/www/public_html"},"subdomain.example.com":{"DocumentRoot":"/var/www/subdomain"}}' > ./signed.crt
```
Notice the `--no-chain` option; if you omitted this option then you would get a fullchain (cert+chain). Also, you can get the chain, cert and fullchain separately:

```sh
python letsacme.py --account-key ./account.key --csr ./domain.csr --config-json ./config.json --cert-file ./signed.cert --chain-file ./chain.crt > ./fullchain.crt
```

If you want to use `--acme-dir`, then:
```sh
python letsacme.py --account-key ./account.key --csr ./domain.csr --acme-dir /var/www/challenges/ --cert-file ./signed.crt --chain-file ./chain.crt > ./fullchain.crt
```

This will create three files: **signed.crt** (the certificate), **chain.crt** (chain), **fullchain.crt** (fullchain).


#5: Install the certificate:
This is an scope beyond the script. You will have to install the certificate manually and setup the server as it requires.

An example for nginx (nginx requires the *fullchain.crt*):

```nginx
server {
    listen 443;
    server_name example.com, www.example.com;

    ssl on;
    ssl_certificate /path/to/fullchain.crt;
    ssl_certificate_key /path/to/domain.key;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA;
    ssl_session_cache shared:SSL:50m;
    ssl_dhparam /path/to/server.dhparam;
    ssl_prefer_server_ciphers on;

    ...the rest of your config
}
```
An example for apache2:
```apache
<VirtualHost *:443>     
        ...other configurations
        SSLEngine on
        SSLCertificateKeyFile /path/to/domain.key
        SSLCertificateFile /path/to/signed.crt
        SSLCertificateChainFile /path/to/chain.crt
</VirtualHost>
```

**For shared servers, it is possible to install the certificate with cpanel or equivalent control panels (if it's supported).**

#6: Setup an auto-renew cron job:
Let's Encrypt certificate only lasts for 90 days. So you need to renew it in a timely manner. You can setup a cron job to do this for you. An example monthly cron job:
```sh
0 0 1 * * /usr/bin/python /path/to/letsacme.py --account-key /path/to/account.key --csr /path/to/domain.csr --config-json /path/to/config.json --cert-file /path/to/signed.crt --chain-file /path/to/chain.crt  > /path/to/fullchain.crt 2>> /var/log/letsacme.log && service apache2 restart
```
But the above code is not recommended as it only tries for once in a month. It may not be enough to renew the certificate on such few tries as they can be timed out due to heavy load or network failures or outage. Let's employ a little retry mechanism. First we need a dedicated script for this:
```sh
#!/bin/sh
while true;do
    if /usr/bin/python /path/to/letsacme.py --account-key /path/to/account.key \
        --csr /path/to/domain.csr \
        --config-json /path/to/config.json \
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
```
The above script won't exit until it finally gets the certificate. It retries in a loop with a random delay in a maximum range of 9999 seconds (~2hrs 46 minutes). Now you can run the above script once every month with an acceptable safety margin. You can minimize the range if you want, for example, for 999 seconds range, change the `head -c 4` part to `head -c 3`.
```sh
0 0 1 * * /bin/sh /path/to/script
```
Even better if you include an initial random delay:
```sh
0 0 1 * * /usr/local/bin/perl -le 'sleep rand 6000' && /bin/sh /path/to/script
```
Let's Encrypt recommends you to run the renewal at least every day. That can be achieved too:
```sh
0 12 * * * /usr/local/bin/perl -le 'sleep rand 43200' && /usr/bin/python /path/to/letsacme.py --account-key /path/to/account.key --csr /path/to/domain.csr --config-json /path/to/config.json --cert-file /path/to/signed1.crt --chain-file /path/to/chain1.crt  > /path/to/fullchain1.crt 2>> /var/log/letsacme.log
```
The above cron job runs the command once every day at a random time as it has to wait until perl gets its' sleep (max range 12 hours (43200s)).

Instead of using the long command, it will be much more readable and easy to maintain if you put those codes into a script and call that script instead:
```sh
/usr/bin/python /path/to/letsacme.py --account-key /path/to/account.key \
    --csr /path/to/domain.csr \
    --config-json /path/to/config.json \
    --cert-file /path/to/signed1.crt \
    --chain-file /path/to/chain1.crt \
    > /path/to/fullchain1.crt \
    2>> /path/to/letsacme.log
```
cron:
```sh
0 12 * * * /usr/local/bin/perl -le 'sleep rand 43200' && /bin/sh /path/to/script
```

**Notice** that the names for the crt files are different (\*1.crt) and there's no server restart command.

We are renewing the certificate every day but that doesn't mean we have to install it every day and restart the server along with it. We can graciously wait for 60 days and then install the certificate as the certificate (\*1.crt) is always renewed. We just need to overwrite the existing one with \*1.crt's. To do that you can set up another cron to overwrite old crt's with new ones and restart the server at a 60 day interval.
```sh
0 0 1 */2 * /bin/cp /old/crt/path/signed1.crt /old/crt/path/signed.crt && /bin/cp /old/crt/path/fullchain1.crt /old/crt/path/fullchain.crt && service apache2 restart
```

#Permissions:

1. **Challenge directory:** The script needs **permission to write** files to the challenge directory which is in the document root of each domain (for the Config JSON). It simply means that the script requires permission to write to your document root. If that seems to be a security issue then you can work it around by creating the challenge directories first. If the challenge directory already exists it will only need permission to write to the challenge directory not the document root. The acme-dir method needs **write permission** to the directory specified by `--acme-dir`.
2. **Account key:** Save the *account.key* file to a secure location. **letsacme** only needs **read permission** to it, so you can revoke write permission from it.
3. **Domain key:** Save the *domain.key* file to a secure location. **letsacme** doesn't use this file. So **no permission** should be allowed for this file.
4. **Cert files:** Save the *signed.crt*, *chain.crt* and *fullchain.crt* in a secure location. **letsacme** needs **write permission** for these files as it will update these files in a timely basis.
5. **Config json:** Save it in a secure location (It stores the path to the document root for each domain). **letsacme** needs only **read permission** to this file.

As you will want to secure yourself as much as you can and thus give as less permission as possible to the script, I suggest you create an extra user for this script and give that user write permission to the challenge directory and the cert files, and read permission to the private key (*account.key*) and the config file (*config.json*) and nothing else.

#Available options:

Run it with `-h` flag to get help.
```sh
python letsacme.py -h
```
It will show you all the available options that are supported by the script. These are the options currently supported:

```sh
  -h, --help            show this help message and exit
  --account-key ACCOUNT_KEY
                        Path to your Let's Encrypt account private key.
  --csr CSR             Path to your certificate signing request.
  --config-json CONFIG_JSON
                        Configuration JSON file. Must contain
                        "DocumentRoot":"/path/to/document/root" entry for each
                        domain.
  --acme-dir ACME_DIR   Path to the .well-known/acme-challenge/ directory
  --cert-file CERT_FILE
                        File to write the certificate to. Overwrites if file
                        exists.
  --chain-file CHAIN_FILE
                        File to write the certificate to. Overwrites if file
                        exists.
  --quiet               Suppress output except for errors.
  --ca CA               Certificate authority, default is Let's Encrypt.
  --no-chain            Fetch chain (CABUNDLE) but do not print it on stdout.
  --no-cert             Fetch certificate but do not print it on stdout.
  --force               Apply force. If a directory is found inside the
                        challenge directory with the same name as challenge
                        token (paranoid), this option will delete the
                        directory and it's content (Use with care).
  --test                Get test certificate (Invalid certificate). This
                        option won't have any effect if --ca is passed.
  --version             Show version info.
```

#Testing:

For testing use the `--test` flag. It will use the staging api and get a test certificate with test chain. Don't test without passing `--test` flag. There's a very low rate limit on how many requests you can send for trusted certificates. On the other hand, the rate limit for the staging api is much larger.
