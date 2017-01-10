[![Build Status](https://travis-ci.org/neurobin/letsacme.svg?branch=release)](https://travis-ci.org/neurobin/letsacme)


The **letsacme** script automates the process of getting a signed TLS/SSL certificate from Let's Encrypt using the ACME protocol. It will need to be run on your server and have **access to your private Let's Encrypt account key**. It gets both the certificate and the chain (CABUNDLE) and prints them on stdout unless specified otherwise.

**PLEASE READ THE SOURCE CODE! YOU MUST TRUST IT WITH YOUR PRIVATE LET'S ENCRYPT ACCOUNT KEY!**

#Dependencies:
1. Python
2. openssl

#How to use:

If you just want to renew an existing certificate, you will only have to do Steps 4~6. 

**For shared servers/hosting:** Get only the certificate (step 1~4) by running the script on your server and then install the certificate with cpanel or equivalent control panels. If you don't want to go all technical about it and just want to follow a step by step process to get the certificate, then [this tutorial](https://neurobin.org/docs/web/letsacme/get-letsencrypt-certficate-for-shared-hosting/) may be the right choice for you.

If you are on a cpanel hosting then [this tutorial](https://neurobin.org/docs/web/fully-automated-letsencrypt-integration-with-cpanel/) will help you automate the whole process.

## 1: Create a Let's Encrypt account private key (if you haven't already):
You must have a public key registered with Let's Encrypt and use the corresponding private key to sign your requests. Thus you first need to create a key, which **letsacme** will use to register an account for you and sign all the following requests.

If you don't understand what the account is for, then this script likely isn't for you. Please, use the official Let's Encrypt client. Or you can read the [howitworks](https://letsencrypt.com/howitworks/technology/) page under the section: **Certificate Issuance and Revocation** to gain a little insight on how certificate issuance works.

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
openssl req -new -sha256 -key domain.key -subj "/C=US/ST=CA/O=MY Org/CN=example.com" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf  <(printf "[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com,DNS:subdomain.example.com,DNS:www.subdomain.com")) -out domain.csr
```
It would probably be easier if you use [gencsr](https://github.com/neurobin/gencsr) to create CSR for multiple domains.

##3: Prepare the challenge directory/s:
**letsacme** provides two methods to prepare the challenge directory/s to complete the acme challenges. One of them is the same as [acme-tiny](https://github.com/diafygi/acme-tiny) (with `--acme-dir`), the other is quite different and simplifies things for users who doesn't have full access to their servers i.e for shared servers or shared hosting. 

**Whatever method you use, note that the challenge directory needs to be accessible with normal http on port 80.**

Otherwise, you may get an **error message** like this one:
```sh
Wrote file to /var/www/public_html/.well-known/acme-challenge/rgGoLnQ8VkBOPyXZn-PkPD-A3KH4_2biYVOxbrYRDuQ, but couldn't download http://example.com/.well-known/acme-challenge/rgGoLnQ8VkBOPyXZn-PkPD-A3KH4_2biYVOxbrYRDuQ
```
See section <a href="#work-around">3.3</a> on how you can work this around.

###3.1: Using acme-dir as in acme-tiny (method 1):
This method is the same as acme-tiny except the fact that letsacme prints a fullchain (cert+chain) on stdout (by default), while acme-tiny prints only the cert. If you provide `--no-chain` option (or equivalent `"NoChain": "False"` in config json) then the output will match that of acme-tiny.

You can pass the acme-dir with `--acme-dir` option or define AcmeDir in json file like `"AcmeDir": "/path/to/acme/dir"`.

This is how you can prepare an acme-dir:
```sh
#make some challenge directory (modify to suit your needs)
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

**You can't use this method on shared server** as most of the shared server won't allow Aliases in AccessFile. For shared server/hosting, you should either use your site's document root as the destination for acme-challenges, or redirect the challenges to a different directory which has a valid and active URL and allows http file download without hindrance. Follow the steps mentioned in section <a href="#work-around">3.3</a> to do that.

###3.2: Using Document Root of each of your sites (method 2):
This method (using document root) is different than the acme-tiny script which this script is based on. Acme-tiny requires you to configure your server for completing the challenge; contrary to that, the intention behind this method is to not have to do anything at all on the server configuration until we finally get the certificate. Instead of setting up your server, you can provide the document root (or path to acme challenge directory) of each domain in a JSON format. It will create the *.well-known/acme-challenge* directory under document root (if not exists already) and put the temporary challenge files there.

**For sites using Wordpress or framework like Laravel, the use of document root as the destination for challenge directory may or may not work. Use the method described in section 3.3 (or section 3.2 if you have full access to the server)**

To pass document root for each of your domain/subdomain you will need create a json file like this:

**config.json:**
```json
{
"example.com": {
    "DocumentRoot":"/var/www/public_html"
    },
"subdomain1.example.com": {
    "DocumentRoot":"/var/www/subdomain1"
    },
"subdomain2.example.com": {
    "DocumentRoot":"/var/www/subdomain2"
    },
"subdomain3.example.com": {
    "DocumentRoot":"/var/www/subdomain3"
    },
"subdomain4.example.com": {
    "DocumentRoot":"/var/www/subdomain4"
    },
"subdomain5.example.com": {
    "DocumentRoot":"/var/www/subdomain5"
    }
}
```

**Note:** You can pass all other options in this config json too. see <a href="#config-json">Options</a> for more details.

<div id="work-around"></div>
###3.3 What will you do if the challenge directory/document root doesn't allow normal http on port 80 (workaround):
**The challenge directory must be accessible with normal http on port 80.**

But this may not be possible all the time. So, what will you do?

And also there's another scenario: if it happens that your site is behind a firewall or your WordPress site or site with Laravel or other tools and framework is preventing direct access to that challenge directory, what will you do?

In the above cases most commonly you will be encountered with an error message like this:

>Wrote file to /var/www/public_html/.well-known/acme-challenge/rgGoLnQ8VkBOPyXZn-PkPD-A3KH4_2biYVOxbrYRDuQ, but couldn't download http://example.com/.well-known/acme-challenge/rgGoLnQ8VkBOPyXZn-PkPD-A3KH4_2biYVOxbrYRDuQ

This means what it **exactly means**, it can't access the challenge files on the URL. It is either being redirected in a weird way or being blocked.

You can however work this around with an effective but peculiar way:

> The basic logic is to redirect all requests to http://example.com/.well-know/acme-challenge/ to another address which permits http access on port 80 and you have access to it's document root (because the script needs to create challenge files there) through terminal.

Create a subdomain (or use an existing one with no additional framework, just plain old http site). Check if the subdomain is accessible (by creating a simple html file inside). Create a directory named `challenge` inside it's document root (don't use `.well-known/acme-challenge` instead of `challenge`, it will create an infinite loop if this new subdomain also contains the following line of redirection code). And then redirect all *.well-know/acme-challenge* requests to all of the domains you want certificate for to this directory of this new subdomain. A mod_rewrite rule for apache2 would be (add it in the .htaccess file or whatever AccessFile you have):
```apache
RewriteRule ^.well-known/acme-challenge/(.*)$ http://challenge.example.com/challenge/$1 [L,R=302]
## If you have any rule that redirects http to https, make sure this rule stays above that one
## To keep it simple, add this rule above all other rewrite rules.
```
And provide the challenge directory as acme-dir (not document root) by either `--acme-dir` option or defining `AcmeDir` json property in config json i.e `--acme-dir /var/www/challenge` or using global acme-dir definition in config json:

```json
"AcmeDir": "/var/www/challenge"
```
**Do not install SSL on this site. If you do, at least do not redirect http to https, otherwise it won't work.**

**Even though it's peculiar and a bit tedious, it is supposed to work with all the situations** as long as the subdomain is properly active. So if you want to move to this method instead of all the other methods available, that wouldn't be a bad idea at all.

##4: Get a signed certificate:
To get a signed certificate, all you need is the private key, the CSR, the JSON configuration file (optional) and a single line of python command (**one of the commands mentioned below**, choose according to your requirements).

If you created a *config.json* (it contains all options) file:
```sh
python letsacme.py --config-json ./config.json > ./fullchain.crt
```
If you didn't create the config.json file and want to use acme-dir, then:
```sh
python letsacme.py --no-chain --account-key ./account.key --csr ./domain.csr --acme-dir /path/to/acme-dir > ./signed.crt
```
Notice the `--no-chain` option; if you omitted this option then you would get a fullchain (cert+chain). Also, you can get the chain, cert and fullchain separately:

```sh
python letsacme.py --account-key ./account.key --csr ./domain.csr --acme-dir /path/to/acme-dir --cert-file ./signed.cert --chain-file ./chain.crt > ./fullchain.crt
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

**For shared servers, it is possible to install the certificate with cpanel or equivalent control panels (if it's supported).** [See this link for how to install it with cpanel](https://neurobin.org/docs/web/installing-tls-ssl-certificate-using-cpanel/)

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
        --acme-dir /path/to/acme-dir \
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

### Another way:
Let's Encrypt recommends you to run the renewal at least every day. That can be achieved too:
```sh
0 12 * * * /usr/local/bin/perl -le 'sleep rand 43200' && /usr/bin/python /path/to/letsacme.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /path/to/acme-dir --cert-file /path/to/signed1.crt --chain-file /path/to/chain1.crt  > /path/to/fullchain1.crt 2>> /var/log/letsacme.log
```
The above cron job runs the command once every day at a random time as it has to wait until perl gets its' sleep (max range 12 hours (43200s)).

Instead of using the long command, it will be much more readable and easy to maintain if you put those codes into a script and call that script instead:
```sh
/usr/bin/python /path/to/letsacme.py --account-key /path/to/account.key \
    --csr /path/to/domain.csr \
    --acme-dir /path/to/acme-dir \
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

1. **Challenge directory:** The script needs **write permission** to the challenge directory (document root or acme-dir). If writing into document root seems to be a security issue then you can work it around by creating the challenge directories first. If the challenge directory already exists it will only need permission to write to the challenge directory not the document root. The acme-dir method needs **write permission** to the directory specified by `--acme-dir`.
2. **Account key:** Save the *account.key* file to a secure location. **letsacme** only needs **read permission** to it.
3. **Domain key:** Save the *domain.key* file to a secure location. **letsacme** doesn't use this file. So **no permission** should be allowed for this file.
4. **Cert files:** Save the *signed.crt*, *chain.crt* and *fullchain.crt* in a secure location. **letsacme** needs **write permission** for these files as it will update these files in a timely basis.
5. **Config json:** Save it in a secure location. **letsacme** needs only **read permission** to this file.

As you will want to secure yourself as much as you can and thus give as less permission as possible to the script, I suggest you create an extra user for this script and give that user write permission to the challenge directory and the cert files, and read permission to the private key (*account.key*) and the config file (*config.json*) and nothing else.

#Options:

Run it with `-h` flag to get help and view the options.
```sh
python letsacme.py -h
```
It will show you all the available options that are supported by the script. These are the options currently supported:

Command line option | Equivalent JSON | Details
---------- | ------------- | -------
`-h`, `--help` | N/A | show this help message and exit
`--account-key PATH` | `"AccountKey": "PATH"` | Path to your Let's Encrypt account private key.
`--csr PATH` | `"CSR": "PATH"` | Path to your certificate signing request.
`--config-json PATH/JSON_STRING` | N/A |Configuration JSON string/file.
`--acme-dir PATH` | `"AcmeDir": "PATH"` | Path to the .well-known/acme-challenge/ directory
`--cert-file PATH` | `"CertFile": "PATH"` | File to write the certificate to. Overwrites if file exists.
`--chain-file PATH` | `"ChainFile": "PATH"` | File to write the certificate to. Overwrites if file exists.
`--quiet` | `"Quiet": "True/False"` | Suppress output except for errors.
`--ca URL` | `"CA": "URL"` | Certificate authority, default is Let's Encrypt.
`--no-chain` | `"NoChain": "True/False"` | Fetch chain (CABUNDLE) but do not print it on stdout.
`--no-cert` | `"NoCert": "True/False"` |       Fetch certificate but do not print it on stdout.
`--force` | `"Force: "True/False"` | Apply force. If a directory is found inside the challenge directory with the same name as challenge token (paranoid), this option will delete the directory and it's content (Use with care).
`--test` | `"Test": "True/False"` | Get test certificate (Invalid certificate). This option won't have any effect if --ca is passed.
`--version` | N/A | Show version info.


#Passing options:

You can either pass the options directly as command line parameters when you run the script or save the options in a configuration json file and pass the path to the configuration file with `--config-json`. The `--config-json` option can also take a raw json string instead of a file path.

If you want to use the acme-dir method, then there's no need to use the config json unless you want to keep your options together, saved somewhere and shorten the command that will be run. But if you use document root as the challenge directory, it is a must to define them in a config json.

**Most of the previous examples show how you can use it without config json**, and this is how you use letsacme with a configuration json:

```sh
python letsacme.py --config-json /path/to/config.json
```
Now letsacme will take all options from that configuration file. `--config-json` can also take a raw JSON string. This may come in handy if you are writing a script and you don't want to create a separate file to put the JSON. In that case, you can put it in a variable and pass the variable as the parameter:

```sh
python letsacme.py --config-json "$conf_json"
```

<div id="config-json"></div>
#Advanced info about the configuration file:

1. Arguments passed in the command line takes priority over properties/options defined in the JSON file.
2. DocumentRoot and AcmeDir can be defined both globally and locally (per domain basis). If any local definition isn't found, then global definition will be searched for.
3. AcmeDir takes priority over DocumentRoot, and local definition takes priority over global definition.
4. The properties (keys/options) are case sensitive.
5. **True** **False** values are case insensitive.
6. If the challenge directory (AcmeDir or DocumentRoot) for non-www site isn't defined, then a definition for it's www version will be searched for and vice versa. If both are defined, they are taken as is.

A full fledged JSON configuration file:
```json
{
"example.com": {
    "DocumentRoot":"/var/www/public_html",
    "_comment":"Global defintion AcmeDir won't be used as DocumentRoot is defined"
    },
"subdomain1.example.com": {
    "DocumentRoot":"/var/www/subdomain1",
    "_comment":"Local defintion of DocumentRoot"
    },
"www.subdomain2.example.com": {
    "AcmeDir":"/var/www/subdomain2",
    "_comment":"Local defintion of AcmeDir"
    },
"subdomain3.example.com": {
    "AcmeDir":"/var/www/subdomain3"
    },
"subdomain4.example.com": {
    "AcmeDir":"/var/www/subdomain4"
    },
"www.subdomain5.example.com": {
    "AcmeDir":"/var/www/subdomain5"
    },
"AccountKey":"account.key",
"CSR": "domain.csr",
"AcmeDir":"/var/www/html",
"DocumentRoot":"/var/www/public_html",
"_comment":"Global definition of DocumentRoot and AcmeDir",
"CertFile":"domain.crt",
"ChainFile":"chain.crt",
"CA":"",
"__comment":"For CA default value will be used. please don't change this option. Use the Test property if you want the staging api.",
"NoChain":"False",
"NoCert":"False",
"Test":"False",
"Force":"False",
"Quiet":"False"
}
```
Another full-fledged JSON file using only a single AcmeDir as challenge directory for every domain:

```json
{
"AcmeDir":"/var/www/challenge",
"_comment":"Global definition of AcmeDir",
"AccountKey":"account.key",
"CSR": "domain.csr",
"CertFile":"domain.crt",
"ChainFile":"chain.crt",
"CA":"",
"__comment":"For CA default value will be used. please don't change this option. Use the Test property if you want the staging api.",
"NoChain":"False",
"NoCert":"False",
"Test":"False",
"Force":"False",
"Quiet":"False"
}
```
The above JSON is exactly for the scenario where you are using it in acme-tiny compatible mode or using the <a href="#work-around">3.3</a> workaround for shared servers.

For <a href="#work-around">3.3</a> workaround, change the AcmeDir to `/var/www/challenge/challenge` where `/var/www/challenge` is the document root of your dedicated http site (challenge.example.com); in that way you can use the exact redirection code mentioned in section <a href="#work-around">3.3</a>.


#Test suit:
The **test** directory contains a simple Bash script named **check.sh**. It creates two temporary local sites (in */tmp*) and <span class="warning">exposes them publicly (careful) on Internet using ngrok</span>, then creates *account key*, *dom.key*, *CSR* for these two sites and gets the certificate and chain. The certificates are retrieved twice: first, by using Document Root and second, by using Acme Dir.

Part of this script requires root privilege (It needs to create custom local sites and configure/restart apache2).

This script depends on various other scripts/tools. An **inst.sh** file is provided to install/download the dependencies.

**Dependencies:**

1. Debian based OS
2. Apache2 server
3. jq
4. ngrok
5. [gencsr](https://github.com/neurobin/gencsr) \[included\]
5. [lampi](https://github.com/neurobin/lampi) \[included\] (This script creates the local sites)

You can get the dependencies by running the *inst.sh* script:

```sh
chmod +x ./test/inst.sh
./test/inst.sh
```
If you already have Apache2 server installed, then just install `jq`. Then download and unzip [ngrok](wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip -O ngrok-stable-linux-amd64.zip) (see *inst.sh* file) in the *test* directory.

After getting the dependencies, you can run **check.sh** to perform the test:

```sh
chmod +x ./test/check.sh
./test/check.sh
```

**Do not run the ./test/travis_check.sh on your local machine.** It's written for [travis build](https://travis-ci.org/neurobin/letsacme) only and contains 
unguarded code that can harm your system.

If you don't want to perform the test yourself but just want to see the outcome, then visit [travis build page for letsacme](https://travis-ci.org/neurobin/letsacme). Travis test uses apache2 Alias in AcmeDir method while the local test uses redirect through .htaccess (the <a href="#work-around">3.3</a> workaround).

**Both tests perform:**

1. A test defining document roots in config json.
2. A test using acme-dir without config json.

