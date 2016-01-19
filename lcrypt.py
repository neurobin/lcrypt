#!/usr/bin/env python
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2

DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
#DEFAULT_CA = "https://acme-v01.api.letsencrypt.org"
ACME_DIR=".well-known/acme-challenge"
VERSION = "0.0.1"
VERSION_INFO="lcrypt version: "+VERSION

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_chain(url,log):
    resp = urlopen(url)
    if(resp.getcode() != 200):
        log.error("E: Failed to fetch chain (CABUNDLE) from: "+url)
        sys.exit()
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(resp.read()).decode('utf8'), 64)))
        
def get_crt(account_key, csr, conf_json, acme_dir, log, CA, force):
    # helper function base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")
                
    def make_dirs(path):
        try:
            os.makedirs(path)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                log.error(str(exception))
                sys.exit(1)
    
    # gets document root from json by domain name
    def get_doc_root(conf_json,dom):
        if dom not in conf_json:
            if(dom.startswith("www.")):
                dom1 = re.sub("^www\\.","",dom)
            else:
                dom1 = "www."+dom
            if dom1 not in conf_json:
                log.error("E: Failed to find "+dom+" or "+dom1+" in "+conf_json)
                sys.exit()
            else: dom = dom1
        try:
            doc_root = conf_json[dom]
            if not os.path.exists(doc_root):
                log.error("E: Document Root: "+doc_root+" doesn't exist")
                sys.exit(1)
            return doc_root
        except:
            log.error("E: Could not get Document Root for \""+dom+"\" in "+json.dumps(conf_json))
            sys.exit()

    # parse account key to get public key
    log.info("Parsing account key...")
    proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        log.error("OpenSSL Error: {0}".format(err))
        sys.exit()
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # helper function make signed requests
    def _send_signed_request(url, payload):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode('utf8'))
        if proc.returncode != 0:
            log.error("OpenSSL Error: {0}".format(err))
            sys.exit()
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": _b64(out),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read(), resp.info()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__), getattr(e, "info", None)()
            
    crt_info = set([])

    # find domains
    log.info("Parsing CSR...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        log.error("Error loading {0}: {1}".format(csr, err))
        sys.exit()
    domains = set([])
    common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
        log.info("CN: "+common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])

    # get the certificate domains and expiration
    log.info("Registering account...")
    code, result, crt_info = _send_signed_request(CA + "/acme/new-reg", {
        "resource": "new-reg",
        "agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf",
    })
    if code == 201:
        log.info("Registered!")
    elif code == 409:
        log.info("Already registered!")
    else:
        log.error("Error registering: {0} {1}".format(code, result))
        sys.exit()
    # verify each domain
    for domain in domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result, crt_info = _send_signed_request(CA + "/acme/new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            log.error("Error requesting challenges: {0} {1}".format(code, result))
            sys.exit()
            
        # create the challenge file
        challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        doc_root = get_doc_root(conf_json,domain)
        chlng_dir = acme_dir.strip(os.path.sep+"/\\"+(os.path.altsep or ""))
        wellknown_path = os.path.join(doc_root, chlng_dir, token)
        index_file_path = os.path.join(wellknown_path,"index.html")
        if os.path.isfile(wellknown_path):
            if(force):
                os.remove(wellknown_path)
                make_dirs(wellknown_path)
            else : 
                log.error(wellknown_path+" is a file. We require it to be a directory. Either delete\
                it manually or run with --force option.")
                sys.exit()
        make_dirs(wellknown_path)
        with open(index_file_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)
        
        # check that the file is in place
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode('utf8').strip()
            assert resp_data == keyauthorization
        except (IOError, AssertionError):
            os.remove(index_file_path)
            os.rmdir(wellknown_path)
            log.error("Wrote file to {0}, but couldn't download {1}".format(
                index_file_path, wellknown_url))
            sys.exit()

        # notify challenge are met
        code, result, crt_info = _send_signed_request(challenge['uri'], {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        if code != 202:
            log.error("Error triggering challenge: {0} {1}".format(code, result))
            sys.exit()

        # wait for challenge to be verified
        while True:
            try:
                resp = urlopen(challenge['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IOError as e:
                log.error("Error checking challenge: {0} {1}".format(
                    e.code, json.loads(e.read().decode('utf8'))))
                sys.exit()
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                log.info("{0} verified!".format(domain))
                os.remove(index_file_path)
                os.rmdir(wellknown_path)
                break
            else:
                log.error("{0} challenge did not pass: {1}".format(
                    domain, challenge_status))
                sys.exit()

    # get the new certificate
    log.info("Signing certificate...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    code, result, crt_info = _send_signed_request(CA + "/acme/new-cert", {
        "resource": "new-cert",
        "csr": _b64(csr_der),
    })
    if code != 201:
        log.error("Error signing certificate: {0} {1}".format(code, result))
        sys.exit()

    # get the chain url
    chain_url = re.match("\\s*<([^>]+)>;rel=\"up\"",crt_info['Link'])
    
    # return signed certificate!
    log.info("Certificate signed!")
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64))), chain_url.group(1)

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS/SSL certificate from
            Let's Encrypt using the ACME protocol. It will need to be run on your server
            and have access to your private account key, so PLEASE READ THROUGH IT! It's
            only ~300 lines, so it won't take long.

            ===Example Usage===
            python lcrypt.py --account-key ./account.key --csr ./domain.csr --config-json '{"example.com":"/usr/share/nginx/html"}' --cert-file signed.crt --chain-file chain.crt
            ===================

            ===Example Crontab Renewal (once per month)===
            0 0 1 * * python /path/to/lcrypt.py --account-key /path/to/account.key --csr /path/to/domain.csr --config-json '{"example.com":"/usr/share/nginx/html"}' > /path/to/signed.crt 2>> /var/log/lcrypt.log
            ==============================================
            """)
    )
    parser.add_argument("--account-key", required=True, help="Path to your Let's Encrypt account private key.")
    parser.add_argument("--csr", required=True, help="Path to your certificate signing request.")
    parser.add_argument("--config-json", required=True, help="Configuration JSON file. Must contain \"domain\":\"Document Root\" entry for each domain.")
    parser.add_argument("--cert-file", default="", help="File to write the certificate to. Overwrites if file exists.")
    parser.add_argument("--chain-file", default="", help="File to write the certificate to. Overwrites if file exists.")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="Suppress output except for errors.")
    parser.add_argument("--ca", default=DEFAULT_CA, help="Certificate authority, default is Let's Encrypt.")
    parser.add_argument("--no-chain",action="store_true", help="Fetch chain (CABUNDLE) but do not print it.")
    parser.add_argument("--no-cert",action="store_true", help="Fetch certificate but do not print it.")
    parser.add_argument("--force",action="store_true", help="Force create challenge dir. If challenge dir is an existing file (created by other letsencrypt clients), this will delete the file and create a directory in its place.")
    parser.add_argument("--version",action="version",version=VERSION_INFO, help="Show version info.")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)
    
    config_json_s = args.config_json
    
    # config_json can point to a file too.
    if os.path.isfile(args.config_json):
        try:
            with open(args.config_json, "r") as f:
                config_json_s = f.read()
        except:
            LOGGER.error("E: Failed to read json file: "+args.config_json)
            sys.exit()
    
    # Now we are sure that config_json_s is a json string, not file
    try:
        conf_json = json.loads(config_json_s)
    except :
        LOGGER.error("E: Failed to parse json")
        sys.exit()
        
    signed_crt, chain_url = get_crt(args.account_key, args.csr, conf_json, acme_dir=ACME_DIR, log=LOGGER, CA=args.ca, force=args.force)
    if(args.cert_file != ""):
        with open(args.cert_file, "w") as f:
            f.write(signed_crt)
    if not args.no_cert: 
        sys.stdout.write(signed_crt)
    
    chain = get_chain(chain_url,log=LOGGER)
    if(args.chain_file != ""):
        with open(args.chain_file, "w") as f:
            f.write(chain)
    if not args.no_chain:
        sys.stdout.write(chain)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
