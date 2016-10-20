#!/usr/bin/env python
"""@package letsacme
################ letsacme ###################
This script automates the process of getting a signed TLS/SSL certificate
from Let's Encrypt using the ACME protocol. It will need to be run on your
server and have access to your private account key.
It gets both the certificate and the chain (CABUNDLE) and
prints them on stdout unless specified otherwise.
"""

import argparse     # argument parser
import subprocess   # Popen
import json         # json.loads
import os           # os.path
import sys          # sys.exit
import base64       # b64encode
import binascii     # unhexlify
import time         # time
import hashlib      # sha256
import re           # regex operation
import copy         # deepcopy
import textwrap     # wrap and dedent
import logging      # Logger
import errno        # EEXIST
import shutil       # rmtree

try: # Python 3
    from urllib.request import urlopen
    from urllib.request import build_opener
    from urllib.request import HTTPRedirectHandler
except ImportError:  # Python 2
    from urllib2 import urlopen
    from urllib2 import HTTPRedirectHandler
    from urllib2 import build_opener

##################### letsacme info #####################
VERSION = "0.1.0"
VERSION_INFO = "letsacme version: "+VERSION
##################### API info ##########################
CA_VALID = "https://acme-v01.api.letsencrypt.org"
CA_TEST = "https://acme-staging.api.letsencrypt.org"
TERMS = 'https://acme-v01.api.letsencrypt.org/terms'
API_DIR_NAME = 'directory'
NEW_REG_KEY = 'new-reg'
NEW_CERT_KEY = 'new-cert'
NEW_AUTHZ_KEY = 'new-authz'
##################### Defaults ##########################
DEFAULT_CA = CA_VALID
API_INFO = set({})
CHALLENGE_DIR = ".well-known/acme-challenge" # used as a fallback in DocumentRoot method
##################### Logger ############################
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)
#########################################################

def get_canonical_url(url, log):
    """
    Follow redirect and return the canonical URL
    """
    try:
        opener = build_opener(HTTPRedirectHandler)
        request = opener.open(url)
        return request.url
    except Exception as e:
        log.error(str(e))
        return url

def get_boolean_options_from_json(conf_json, ncn, ncrt, tst, frc):
    """
    Parse config json for boolean options and return them sequentially
    """
    keys = ['NoChain', 'NoCert', 'Test', 'Force']
    pvalue = [ncn, ncrt, tst, frc]
    value = []
    for i, key in enumerate(keys, start=0):
        if not pvalue[i]:
            if key in conf_json:
                if conf_json[key]:
                    if conf_json[key].lower() == "true":
                        value.append(True)
                    else: value.append(False)
                else: value.append(False)
            else: value.append(False)
        else: value.append(pvalue[i])
    return value[0], value[1], value[2], value[3]

def get_options_from_json(conf_json, ac, csr, acmd, crtf, chnf, ca):
    """
    Parse key-value options from config json and return the values sequentially
    """
    keys = ['AccountKey', 'CSR', 'AcmeDir', 'CertFile', 'ChainFile', 'CA']
    pvalue = [ac, csr, acmd, crtf, chnf, ca]
    value = []
    for i, key in enumerate(keys, start=0):
        if not pvalue[i]:
            if key in conf_json:
                if conf_json[key]:
                    value.append(conf_json[key])
                else: value.append(None)
            else: value.append(None)
        else: value.append(pvalue[i])
    return value[0], value[1], value[2], value[3], value[4], value[5]

def get_chain(url, log):
    """
    Download chain from chain url and return it
    """
    resp = urlopen(url)
    if resp.getcode() != 200:
        log.error("E: Failed to fetch chain (CABUNDLE) from: "+url)
        sys.exit(1)
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(resp.read()).decode('utf8'), 64)))

def get_crt(account_key, csr, conf_json, challenge_dir, acme_dir, log, CA, force):
    """
    Register account, parse CSR, complete challenges and finally
    get the signed SSL certificate and return it.
    """
    # helper function base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    def make_dirs(path):
        """
        Make directories including parent directories (if not exist)
        """
        try:
            os.makedirs(path)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                log.error(str(exception))
                sys.exit(1)

    # get challenge directory from json by domain name
    def get_challenge_dir(conf_json, dom):
        """
        Get the challenge directory path from config json
        """
        if dom not in conf_json:
            if dom.startswith("www."):
                dom1 = re.sub("^www\\.", "", dom)
            else:
                dom1 = "www."+dom
            if dom1 in conf_json:
                dom = dom1
        try:
            if dom in conf_json:
                if 'AcmeDir' in conf_json[dom]:
                    return None, conf_json[dom]['AcmeDir']
                elif 'DocumentRoot' in conf_json[dom]:
                    return  conf_json[dom]['DocumentRoot'], None
            # if none is given we will try to take challenge dir from global options
            if 'AcmeDir' in conf_json:
                return None, conf_json['AcmeDir']
            elif 'DocumentRoot' in conf_json:
                return conf_json['DocumentRoot'], None
            else:
                log.error("E: There is no valid entry for \"DocumentRoot\" or \"AcmeDir\" in\n" +
                          json.dumps(conf_json[dom], indent=4, sort_keys=True))
                sys.exit(1)
            if not os.path.exists(doc_root) and (doc_root != ""):
                log.error("E: Document Root: "+doc_root+" doesn't exist")
                sys.exit(1)
        except KeyError:
            log.error("E: There is no entry for "+dom+" in\n" +
                      json.dumps(conf_json, indent=4, sort_keys=True))
            sys.exit(1)
        except Exception as e:
            log.error("E: Could not get a valid Document Root or Acme Dir for \"" +
                      dom+"\" from: \n" +json.dumps(conf_json, indent=4, sort_keys=True)+
                      '\n'+str(e))
            sys.exit(1)

    # parse account key to get public key
    log.info("Parsing account key...")
    proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        log.error("\tOpenSSL Error: {0}".format(err))
        sys.exit(1)
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
    log.info('\tParsed!')

    # helper function make signed requests
    def _send_signed_request(url, payload):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode('utf8'))
        if proc.returncode != 0:
            log.error("OpenSSL Error: {0}".format(err))
            sys.exit(1)
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": _b64(out),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read(), resp.info()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__), getattr(e, "info",
                                                                                    None)()

    crt_info = set([])

    # find domains
    log.info("Parsing CSR...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        log.error("\tError loading {0}: {1}".format(csr, err))
        sys.exit(1)
    domains = set([])
    common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
        log.info("\tCN: "+common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n",
                                  out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    log.info('\tParsed!')

    # get the certificate domains and expiration
    log.info("Registering account...")
    agreement_url = get_canonical_url(TERMS, log)
    code, result, crt_info = _send_signed_request(API_INFO[NEW_REG_KEY], {
        "resource": NEW_REG_KEY,
        "agreement": agreement_url,
    })
    if code == 201:
        log.info("\tRegistered!")
    elif code == 409:
        log.info("\tAlready registered!")
    else:
        log.error("\tError registering: {0} {1}".format(code, result))
        sys.exit(1)
    # verify each domain
    for domain in domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result, crt_info = _send_signed_request(API_INFO[NEW_AUTHZ_KEY], {
            "resource": NEW_AUTHZ_KEY,
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            log.error("\tError requesting challenges: {0} {1}".format(code, result))
            sys.exit(1)

        # create the challenge file
        challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] \
                                                    if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        wellknown_url = None
        if 'validationRecord' in challenge:
            for item in challenge['validationRecord']:
                if 'url' in item:
                    res_m = re.match('.*://'+domain+r'/([\w\W]*)/'+token, item['url'])
                    if res_m:
                        challenge_dir = res_m.group(1)
                        wellknown_url = res_m.group(0)
                        log.info('\tWell known path was parsed: '+challenge_dir)
        # paranoid check
        token = token.strip(os.path.sep+"/\\"+(os.path.altsep or ""))
         # the number 4 (3 is enough) takes account for .. scenerio
        if not re.match("^[^"+os.path.sep+"/\\\\"+(os.path.altsep or "")+"]{4,}$", token):
            log.error("\tE: Invalid and possibly dangerous token.")
            sys.exit(1)
        # take either acme-dir or document dir method
        if acme_dir and not conf_json:
            make_dirs(acme_dir)  # create the challenge dir if not exists
            wellknown_path = os.path.join(acme_dir, token)
        elif conf_json:
            doc_root, acme_dir = get_challenge_dir(conf_json, domain)
            if doc_root:
                chlng_dir = challenge_dir.strip(os.path.sep+"/\\"+(os.path.altsep or ""))
                # create the challenge dir if not exists
                make_dirs(os.path.join(doc_root, chlng_dir))
                wellknown_path = os.path.join(doc_root, chlng_dir, token)
            elif acme_dir:
                # create the challenge dir if not exists
                make_dirs(acme_dir)
                wellknown_path = os.path.join(acme_dir, token)
            else:
                log.error("\tCouldn't get DocumentRoot or AcmeDir from: \n"+
                          json.dumps(conf_json, indent=4, sort_keys=True))
                sys.exit(1)
        else:
            log.error("\tChallenge directory not given")
            sys.exit(1)
        # another paranoid check
        if os.path.isdir(wellknown_path):
            log.warning("\tW: "+wellknown_path+" exists.")
            try:
                os.rmdir(wellknown_path)
            except OSError:
                if force:
                    try:
                        # This is why we have done paranoid check on token
                        shutil.rmtree(wellknown_path)
                        # though it itself is inside a paranoid check
                        # which will probably never be reached
                        log.info("\tRemoved "+wellknown_path)
                    except Exception as e:
                        log.error("\tE: Failed to remove "+wellknown_path+'\n'+str(e))
                        sys.exit(1)
                else:
                    log.error("\tE: "+wellknown_path+" is a directory. \
                              It shouldn't even exist in normal cases. \
                              Try --force option if you are sure about \
                              deleting it and all of its' content")
                    sys.exit(1)
        try:
            with open(wellknown_path, "w") as wellknown_file:
                wellknown_file.write(keyauthorization)
                #log.info("\tChallenge path: "+wellknown_path+"\n\tAuth: "+keyauthorization)
        except Exception as e:
            log.error(str(e))
            sys.exit(1)

        # check that the file is in place
        if not wellknown_url:
            wellknown_url = ("http://{0}/"+challenge_dir+"/{1}").format(domain, token)
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode('utf8').strip()
            assert resp_data == keyauthorization
        except (IOError, AssertionError):
            os.remove(wellknown_path)
            log.error("\tWrote file to {0}, but couldn't download {1}".format(
                wellknown_path, wellknown_url))
            sys.exit(1)

        # notify challenge is met
        code, result, crt_info = _send_signed_request(challenge['uri'], {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        if code != 202:
            log.error("\tError triggering challenge: {0} {1}".format(code, result.read()))
            os.remove(wellknown_path)
            sys.exit(1)

        # wait for challenge to be verified
        while True:
            try:
                resp = urlopen(challenge['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IOError as e:
                log.error("\tError checking challenge: {0} {1}\n{2}".format(
                    resp.code, json.dumps(resp.read().decode('utf8'), indent=4), str(e)))
                os.remove(wellknown_path)
                sys.exit(1)
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                log.info("\tverified!")
                os.remove(wellknown_path)
                break
            else:
                log.error("\t{0} challenge did not pass: {1}".format(
                    domain, challenge_status))
                os.remove(wellknown_path)
                sys.exit(1)

    # get the new certificate
    if CA == CA_TEST:
        test_mode = " (test mode)"
    else: test_mode = ""
    log.info("Signing certificate..."+test_mode)
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    code, result, crt_info = _send_signed_request(API_INFO[NEW_CERT_KEY], {
        "resource": NEW_CERT_KEY,
        "csr": _b64(csr_der),
    })
    if code != 201:
        log.error("\tError signing certificate: {0} {1}".format(code, result))
        sys.exit(1)

    log.info('\tParsing chain url...')
    res_m = re.match("\\s*<([^>]+)>;rel=\"up\"", crt_info['Link'])
    if res_m:
        chain_url = res_m.group(1)
        log.info('\tParsed chain url')
    else:
        chain_url = None
        log.error('\tW: Failed to parse chain url!')

    # return signed certificate!
    log.info("\tSigned!"+test_mode)
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64))), chain_url

def main(argv):
    """
    main function
    Parse arguments and run helper functions to get the certs
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS/SSL certificate from
            Let's Encrypt using the ACME protocol. It will need to be run on your server
            and have access to your private account key, so PLEASE READ THROUGH IT!.

            ===Example Usage===
            python letsacme.py --config-json /path/to/config.json
            ===================

            ===Example Crontab Renewal (once per month)===
            0 0 1 * * python /path/to/letsacme.py --config-json /path/to/config.json > /path/to/full-chain.crt 2>> /path/to/letsacme.log
            ==============================================
            """)
    )
    parser.add_argument("--account-key", help="Path to your Let's Encrypt account private key.")
    parser.add_argument("--csr", help="Path to your certificate signing request.")
    parser.add_argument("--config-json", default=None, help="Configuration JSON file. \
                        Must contain \"DocumentRoot\":\"/path/to/document/root\" entry \
                        for each domain.")
    parser.add_argument("--acme-dir", default=None, help="Path to the acme challenge directory")
    parser.add_argument("--cert-file", default="", help="File to write the certificate to. \
                        Overwrites if file exists.")
    parser.add_argument("--chain-file", default="", help="File to write the certificate to. \
                        Overwrites if file exists.")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="Suppress \
                        output except for errors.")
    parser.add_argument("--ca", default=None, help="Certificate authority, default is Let's \
                        Encrypt.")
    parser.add_argument("--no-chain", action="store_true", help="Fetch chain (CABUNDLE) but\
                        do not print it on stdout.")
    parser.add_argument("--no-cert", action="store_true", help="Fetch certificate but do not\
                        print it on stdout.")
    parser.add_argument("--force", action="store_true", help="Apply force. If a directory\
                        is found inside the challenge directory with the same name as\
                        challenge token (paranoid), this option will delete the directory\
                        and it's content (Use with care).")
    parser.add_argument("--test", action="store_true", help="Get test certificate (Invalid \
                        certificate). This option won't have any effect if --ca is passed.")
    parser.add_argument("--version", action="version", version=VERSION_INFO, help="Show version \
                        info.")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)
    if not args.config_json:
        if not args.acme_dir:
            parser.error("One of --config-json or --acme-dir must be given")

    # parse config_json
    conf_json = None
    if args.config_json:
        config_json_s = args.config_json
        # config_json can point to a file too.
        if os.path.isfile(args.config_json):
            try:
                with open(args.config_json, "r") as f:
                    config_json_s = f.read()
            except Exception as e:
                LOGGER.error("E: Failed to read json file: "+args.config_json+"\n"+str(e))
                sys.exit(1)
        # Now we are sure that config_json_s is a json string, not file
        try:
            conf_json = json.loads(config_json_s)
        except Exception as e:
            LOGGER.error("E: Failed to parse json"+"\n"+str(e))
            sys.exit(1)

    # get options from JSON
    if args.config_json:
        args.account_key, args.csr, args.acme_dir, args.cert_file,\
        args.chain_file, args.ca = get_options_from_json(conf_json,
                                                         args.account_key,
                                                         args.csr,
                                                         args.acme_dir,
                                                         args.cert_file,
                                                         args.chain_file,
                                                         args.ca)
        args.no_chain, args.no_cert, args.test, args.force = \
                    get_boolean_options_from_json(conf_json, args.no_chain,
                                                  args.no_cert, args.test, args.force)

    if not args.quiet:
        if conf_json and 'Quiet' in conf_json:
            LOGGER.warning("--quiet can not be passed inside configuration JSON.\
                           It will be ignored.")

    # show error in case args are missing
    if not args.account_key:
        LOGGER.error("E: Account key path not specified.")
        sys.exit(1)
    if not args.csr:
        LOGGER.error("E: CSR path not specified")
        sys.exit(1)
    if not args.config_json and not args.acme_dir:
        LOGGER.error("E: Either --acme-dir or --config-json must be given")
        sys.exit(1)
    # we need to set a default CA if not specified
    if not args.ca:
        if args.test: args.ca = CA_TEST
        else: args.ca = DEFAULT_CA

    global API_INFO # this is where we will pull our information from
    API_INFO = json.loads(urlopen(args.ca+'/'+API_DIR_NAME).read().decode('utf8'))

    # lets do the main task
    signed_crt, chain_url = get_crt(args.account_key, args.csr,
                                    conf_json, challenge_dir=CHALLENGE_DIR,
                                    acme_dir=args.acme_dir, log=LOGGER,
                                    CA=args.ca, force=args.force)

    if args.cert_file:
        with open(args.cert_file, "w") as f:
            f.write(signed_crt)
    if not args.no_cert:
        sys.stdout.write(signed_crt)

    if chain_url:
        chain = get_chain(chain_url, log=LOGGER)
        if args.chain_file:
            with open(args.chain_file, "w") as f:
                f.write(chain)
        if not args.no_chain:
            sys.stdout.write(chain)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
