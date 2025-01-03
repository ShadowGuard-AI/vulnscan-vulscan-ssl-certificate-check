import argparse
import logging
import requests
import ssl
import socket
from datetime import datetime
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Checks the SSL/TLS certificate of a given host.")
    parser.add_argument("host", type=str, help="The hostname or IP address to check.")
    parser.add_argument("-p", "--port", type=int, default=443, help="The port to connect to (default: 443).")
    return parser.parse_args()

def get_ssl_certificate(host, port):
    """
    Retrieves the SSL/TLS certificate from a given host and port.

    Args:
        host (str): The hostname or IP address.
        port (int): The port to connect to.

    Returns:
        crypto.X509: The SSL/TLS certificate object or None on failure.
    """
    try:
        # Create a socket and connect to the host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Set a timeout to avoid indefinite blocking
        sock.connect((host, port))
        
        # Wrap the socket in an SSL/TLS connection
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        
        # Get the certificate in binary format
        cert_der = ssl_sock.getpeercert(binary_form=True)
        
        # Convert the DER-encoded certificate to an X.509 certificate object
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
        return cert
    except socket.timeout:
        logging.error(f"Connection to {host}:{port} timed out.")
        return None
    except socket.gaierror:
        logging.error(f"Could not resolve hostname: {host}")
        return None
    except ConnectionRefusedError:
        logging.error(f"Connection refused to {host}:{port}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None
    finally:
        if 'ssl_sock' in locals() and ssl_sock:
            ssl_sock.close()
        if 'sock' in locals() and sock:
            sock.close()
    
def check_certificate_validity(cert):
    """
    Checks the validity of the SSL/TLS certificate.

    Args:
        cert (crypto.X509): The SSL/TLS certificate object.

    Returns:
        tuple: A tuple containing (is_valid, expiry_date, days_to_expiry) or (False, None, None) on failure.
    """
    if not cert:
        return False, None, None
    
    try:
        not_before = datetime.strptime(str(cert.get_notBefore())[2:-1], '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(str(cert.get_notAfter())[2:-1], '%Y%m%d%H%M%SZ')
        now = datetime.now()
        is_valid = not_before <= now <= not_after
        days_to_expiry = (not_after - now).days if is_valid else None
        return is_valid, not_after, days_to_expiry
    except Exception as e:
        logging.error(f"Error during certificate validity check: {e}")
        return False, None, None

def get_certificate_ciphers(host, port):
    """
    Retrieves the ciphers used in the SSL/TLS connection.

    Args:
        host (str): The hostname or IP address.
        port (int): The port to connect to.

    Returns:
        list: A list of cipher names used, or None on failure.
    """
    try:
        # Create a socket and connect to the host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        # Wrap the socket in an SSL/TLS connection
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        
        # Get the cipher used for the connection
        cipher = ssl_sock.cipher()
        return [cipher]
    
    except socket.timeout:
        logging.error(f"Connection to {host}:{port} timed out.")
        return None
    except socket.gaierror:
        logging.error(f"Could not resolve hostname: {host}")
        return None
    except ConnectionRefusedError:
        logging.error(f"Connection refused to {host}:{port}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None
    finally:
        if 'ssl_sock' in locals() and ssl_sock:
            ssl_sock.close()
        if 'sock' in locals() and sock:
            sock.close()

def get_certificate_details(cert):
    """
    Extracts and prints relevant details from the certificate.

    Args:
        cert (crypto.X509): The SSL/TLS certificate object.
    """
    if not cert:
        logging.error("No certificate provided for details extraction.")
        return
    try:
        # Extract subject details
        subject = cert.get_subject()
        common_name = subject.CN
        
        # Extract issuer details
        issuer = cert.get_issuer()
        issuer_common_name = issuer.CN
        
        # Extract serial number
        serial_number = cert.get_serial_number()
       
        # Extract certificate algorithm
        cert_algorithm = cert.get_signature_algorithm()

        # Extract certificate fingerprints
        fingerprint_sha1 = cert.digest('sha1').decode('utf-8')
        fingerprint_sha256 = cert.digest('sha256').decode('utf-8')
        
        # Convert certificate to a cryptography object to read extensions
        cert_crypto = x509.load_der_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert), default_backend())
        
        # Extract subject alternative names
        san_extensions = cert_crypto.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_list = san_extensions.value.get_values_for_type(x509.DNSName) if san_extensions else []
        
        # Display the extracted details
        logging.info("Certificate Details:")
        logging.info(f"  Subject Common Name: {common_name}")
        logging.info(f"  Issuer Common Name: {issuer_common_name}")
        logging.info(f"  Serial Number: {serial_number}")
        logging.info(f"  Signature Algorithm: {cert_algorithm}")
        logging.info(f"  Fingerprint (SHA1): {fingerprint_sha1}")
        logging.info(f"  Fingerprint (SHA256): {fingerprint_sha256}")
        if san_list:
           logging.info(f"  Subject Alternative Names: {', '.join(san_list)}")

    except Exception as e:
       logging.error(f"Error extracting certificate details: {e}")

def main():
    """
    Main function to execute the SSL/TLS certificate check.
    """
    args = setup_argparse()
    host = args.host
    port = args.port

    if not isinstance(port, int) or port <= 0 or port > 65535:
        logging.error("Invalid port number. Please provide a valid port number between 1 and 65535.")
        return

    logging.info(f"Checking SSL certificate for {host}:{port}")
    
    cert = get_ssl_certificate(host, port)

    if not cert:
       logging.error(f"Failed to retrieve SSL certificate for {host}:{port}")
       return
    
    is_valid, expiry_date, days_to_expiry = check_certificate_validity(cert)
    if is_valid:
        logging.info("Certificate is valid.")
        if expiry_date and days_to_expiry is not None:
             logging.info(f"Certificate expires on: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')} (in {days_to_expiry} days)")
    else:
        logging.warning("Certificate is invalid or has expired.")
        if expiry_date:
            logging.warning(f"Certificate expired on: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}")


    ciphers = get_certificate_ciphers(host, port)
    if ciphers:
        logging.info(f"Ciphers used: {', '.join([cipher[0] for cipher in ciphers])}")
    
    get_certificate_details(cert)

if __name__ == "__main__":
    main()