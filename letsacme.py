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
    from urllib.error import HTTPError
    from urllib.error import URLError
except ImportError:  # Python 2
    from urllib2 import urlopen
    from urllib2 import HTTPRedirectHandler
    from urllib2 import build_opener
    from urllib2 import HTTPError
    from urllib2 import URLError

##################### letsacme info #####################
VERSION = "0.1.3"
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
# used as a fallback in DocumentRoot method:
WELL_KNOWN_DIR = ".well-known/acme-challenge"
##################### Logger ############################
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)
#########################################################

def error_exit(msg, log):
    """Print error message and exit with 1 exit status"""
    log.error(msg)
    sys.exit(1)

def get_canonical_url(url, log):
    """Follow redirect and return the canonical URL"""
    try:
        opener = build_opener(HTTPRedirectHandler)
        request = opener.open(url)
        return request.url
    except (URLError, HTTPError) as err:
        log.error(str(err))
        return url

def get_boolean_options_from_json(conf_json, ncn, ncrt, tst, frc, quiet):
    """Parse config json for boolean options and return them sequentially.
    It takes prioritised values as params. Among these values, non-None/True values are
    preserved and their values in config json are ignored."""
    opt = {'NoChain':ncn, 'NoCert':ncrt, 'Test':tst, 'Force':frc, 'Quiet': quiet}
    for key in opt:
        if not opt[key] and key in conf_json and conf_json[key].lower() == "true":
            opt[key] = True
            continue
    return opt['NoChain'], opt['NoCert'], opt['Test'], opt['Force'], opt['Quiet']

def get_options_from_json(conf_json, ack, csr, acmd, crtf, chnf, ca):
    """Parse key-value options from config json and return the values sequentially.
    It takes prioritised values as params. Among these values, non-None values are
    preserved and their values in config json are ignored."""
    opt = {'AccountKey':ack, 'CSR':csr, 'AcmeDir':acmd, 'CertFile':crtf, 'ChainFile':chnf, 'CA':ca}
    for key in opt:
        if not opt[key] and key in conf_json and conf_json[key]:
            opt[key] = conf_json[key]
            continue
        opt[key] = None if opt[key] == '' or opt[key] == '.' or opt[key] == '..' else opt[key]
    return opt['AccountKey'], opt['CSR'], opt['AcmeDir'], opt['CertFile'], opt['ChainFile'],\
           opt['CA']

def get_chain(url, log):
    """Download chain from chain url and return it"""
    resp = urlopen(url)
    if resp.getcode() != 200:
        error_exit("E: Failed to fetch chain (CABUNDLE) from: "+url, log)
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(resp.read()).decode('utf8'), 64)))

def write_file(path, content, log, exc=True):
    """Write content to the file specified by path"""
    try:
        with open(path, "w") as fileh:
            fileh.write(content)
    except IOError as err:
        log.error(str(err))
        if exc:
            sys.exit(1)


def get_crt(account_key, csr, conf_json, well_known_dir, acme_dir, log, CA, force):
    """Register account, parse CSR, complete challenges and finally
    get the signed SSL certificate and return it."""
    def _b64(bcont):
        """helper function base64 encode for jose spec"""
        return base64.urlsafe_b64encode(bcont).decode('utf8').replace("=", "")

    def make_dirs(path):
        """Make directories including parent directories (if not exist)"""
        try:
            os.makedirs(path)
        except OSError as err:
            if err.errno != errno.EEXIST:
                error_exit('E: '+str(err), log)

    # get challenge directory from json by domain name
    def get_challenge_dir(conf_json, dom, acmed):
        """Get the challenge directory path from config json"""
        if conf_json:
            if dom not in conf_json:
                if re.match(r'www[^.]*\.', dom):
                    dom1 = re.sub(r"^www[^.]*\.", "", dom)
                else:
                    dom1 = "www."+dom
                if dom1 in conf_json:
                    dom = dom1
            # no else
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
        elif acmed:
            return None, acmed
        else:
            error_exit("E: There is no valid entry for \"DocumentRoot\" or \"AcmeDir\" for \
                       the domain '"+dom+"' in\n" +
                       json.dumps(conf_json, indent=4, sort_keys=True), log)

    # parse account key to get public key
    log.info("Parsing account key...")
    proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        error_exit("\tE: OpenSSL Error: {0}".format(err), log)
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
            error_exit("E: OpenSSL Error: {0}".format(err), log)
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": _b64(out),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read(), resp.info()
        except IOError as err:
            return getattr(err, "code", None), getattr(err, "read", err.__str__),\
                           getattr(err, "info", None)()

    crt_info = set([])

    # find domains
    log.info("Parsing CSR...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        error_exit("\tE: Error loading {0}: {1}".format(csr, err), log)
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
        error_exit("\tE: Error registering: {0} {1}".format(code, result), log)
    # verify each domain
    for domain in domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result, crt_info = _send_signed_request(API_INFO[NEW_AUTHZ_KEY], {
            "resource": NEW_AUTHZ_KEY,
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            error_exit("\tE: Error requesting challenges: {0} {1}".format(code, result), log)

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
                        well_known_dir = res_m.group(1)
                        wellknown_url = res_m.group(0)
                        log.info('\tWell known path was parsed: '+well_known_dir)
        # paranoid check
        if os.path.sep in token or (os.path.altsep or '\\') in token or not token:
            error_exit("\tE: Invalid and possibly dangerous token.", log)
        # take either acme-dir or document dir method
        doc_root, acme_dir = get_challenge_dir(conf_json, domain, acme_dir)
        if acme_dir:
            chlng = acme_dir.rstrip(os.path.sep+(os.path.altsep or "\\"))
            make_dirs(chlng)
            wellknown_path = os.path.join(chlng, token)
        elif doc_root:
            doc_root = doc_root.rstrip(os.path.sep+(os.path.altsep or "\\"))
            chlng = os.path.join(doc_root, well_known_dir.strip(os.path.sep+\
                                         (os.path.altsep or "\\")))
            make_dirs(chlng)
            wellknown_path = os.path.join(chlng, token)
        else:
            error_exit("\tE: Couldn't get DocumentRoot or AcmeDir for domain: "+domain, log)
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
                    except OSError as err:
                        error_exit("\tE: Failed to remove "+wellknown_path+'\n'+str(err), log)
                else:
                    error_exit("\tE: "+wellknown_path+" is a directory. \
                               It shouldn't even exist in normal cases. \
                               Try --force option if you are sure about \
                               deleting it and all of its' content", log)

        write_file(wellknown_path, keyauthorization, log)

        # check that the file is in place
        if not wellknown_url:
            wellknown_url = ("http://{0}/"+well_known_dir+"/{1}").format(domain, token)
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode('utf8').strip()
            assert resp_data == keyauthorization
        except (IOError, AssertionError):
            os.remove(wellknown_path)
            error_exit("\tE: Wrote file to {0}, but couldn't download {1}".format(\
                       wellknown_path, wellknown_url), log)

        # notify challenge is met
        code, result, crt_info = _send_signed_request(challenge['uri'], {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        if code != 202:
            os.remove(wellknown_path)
            error_exit("\tE: Error triggering challenge: {0} {1}".format(code, result.read()), log)

        # wait for challenge to be verified
        while True:
            try:
                resp = urlopen(challenge['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IOError as err:
                os.remove(wellknown_path)
                error_exit("\tE: Error checking challenge: {0} {1}\n{2}".format(\
                           resp.code, json.dumps(resp.read().decode('utf8'),\
                           indent=4), str(err)), log)
            if challenge_status['status'] == "pending":
                time.sleep(1)
            elif challenge_status['status'] == "valid":
                os.remove(wellknown_path)
                log.info("\tverified!")
                break
            else:
                os.remove(wellknown_path)
                error_exit("\tE: {0} challenge did not pass: {1}".format(\
                           domain, challenge_status), log)

    # get the new certificate
    test_mode = " (test mode)" if CA == CA_TEST else ""
    log.info("Signing certificate..."+test_mode)
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    code, result, crt_info = _send_signed_request(API_INFO[NEW_CERT_KEY], {
        "resource": NEW_CERT_KEY,
        "csr": _b64(csr_der),
    })
    if code != 201:
        error_exit("\tE: Error signing certificate: {0} {1}".format(code, result), log)

    log.info('\tParsing chain url...')
    res_m = re.match("\\s*<([^>]+)>;rel=\"up\"", crt_info['Link'])
    chain_url = res_m.group(1) if res_m else None
    if not chain_url:
        log.error('\tW: Failed to parse chain url!')

    # return signed certificate!
    log.info("\tSigned!"+test_mode)
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64))), chain_url

def main(argv):
    """Parse arguments and run helper functions to get the certs"""
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
    parser.add_argument("--config-json", default=None, help="Configuration JSON string/file. \
                        Must contain \"DocumentRoot\":\"/path/to/document/root\" entry \
                        for each domain.")
    parser.add_argument("--acme-dir", default=None, help="Path to the acme challenge directory")
    parser.add_argument("--cert-file", default=None, help="File to write the certificate to. \
                        Overwrites if file exists.")
    parser.add_argument("--chain-file", default=None, help="File to write the certificate to. \
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
    if not args.config_json and not args.acme_dir:
        parser.error("One of --config-json or --acme-dir must be given")

    # parse config_json
    conf_json = None
    if args.config_json:
        config_json_s = args.config_json
        # config_json can point to a file too.
        if os.path.isfile(args.config_json):
            try:
                with open(args.config_json, "r") as fileh:
                    config_json_s = fileh.read()
            except IOError as err:
                error_exit("E: Failed to read json file: "+args.config_json+"\n"+str(err),
                           LOGGER)
        # Now we are sure that config_json_s is a json string, not file
        try:
            conf_json = json.loads(config_json_s)
        except ValueError as err:
            error_exit("E: Failed to parse json"+"\n"+str(err), log=LOGGER)
        args.account_key, args.csr, args.acme_dir, args.cert_file,\
        args.chain_file, args.ca = get_options_from_json(conf_json,
                                                         args.account_key,
                                                         args.csr,
                                                         args.acme_dir,
                                                         args.cert_file,
                                                         args.chain_file,
                                                         args.ca)
        args.no_chain, args.no_cert, args.test, args.force, args.quiet = \
                    get_boolean_options_from_json(conf_json, args.no_chain, args.no_cert,
                                                  args.test, args.force, args.quiet)

    LOGGER.setLevel(logging.ERROR if args.quiet else LOGGER.level)

    # show error in case args are missing
    if not args.account_key:
        error_exit("E: Account key path not specified.", LOGGER)
    if not args.csr:
        error_exit("E: CSR path not specified", LOGGER)
    if not args.config_json and not args.acme_dir:
        error_exit("E: Either --acme-dir or --config-json must be given", log=LOGGER)
    # we need to set a default CA if not specified
    if not args.ca:
        args.ca = CA_TEST if args.test else DEFAULT_CA

    global API_INFO # this is where we will pull our information from
    API_INFO = json.loads(urlopen(args.ca+'/'+API_DIR_NAME).read().decode('utf8'))

    # lets do the main task
    signed_crt, chain_url = get_crt(args.account_key, args.csr,
                                    conf_json, well_known_dir=WELL_KNOWN_DIR,
                                    acme_dir=args.acme_dir, log=LOGGER,
                                    CA=args.ca, force=args.force)

    if args.cert_file:
        write_file(args.cert_file, signed_crt, LOGGER, False)
    if not args.no_cert:
        sys.stdout.write(signed_crt)

    if chain_url:
        chain = get_chain(chain_url, log=LOGGER)
        if args.chain_file:
            write_file(args.chain_file, chain, LOGGER, False)
        if not args.no_chain:
            sys.stdout.write(chain)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
